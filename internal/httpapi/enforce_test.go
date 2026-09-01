package httpapi_test

// The fail-open/fail-closed policy is the decision the principal review called the most
// important one in the whole slice, and a policy that lives only in a table is a policy that
// changes without anyone noticing. These tests are what make it invariant: each one fails if
// a class's behaviour is edited.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/foundation-reference/internal/httpapi"
	"github.com/anshacerbia2/foundation-reference/internal/projection"
)

type stubProjection struct {
	age    time.Duration
	ageErr error

	record    projection.Record
	lookupErr error
}

func (s stubProjection) Age(context.Context) (time.Duration, error) {
	return s.age, s.ageErr
}

func (s stubProjection) Lookup(context.Context, id.UUID, id.UUID) (projection.Record, error) {
	return s.record, s.lookupErr
}

type stubAuthority struct {
	granted bool
	err     error
}

func (s stubAuthority) Verify(context.Context, id.UUID, id.UUID) (httpapi.Verdict, error) {
	return httpapi.Verdict{Granted: s.granted, MembershipVersion: 4, TenantSecurityVersion: 1}, s.err
}

// membership returns a fixture identifier used for both the tenant and the principal: the
// enforcer treats them as opaque, and using one value keeps the call sites readable.
func membership(t *testing.T) id.UUID {
	t.Helper()
	parsed, err := id.Parse("11111111-1111-4111-8111-11111111111a")
	if err != nil {
		t.Fatalf("parsing the fixture identifier: %v", err)
	}
	return parsed
}

func enforcer(t *testing.T, p httpapi.Projection, a httpapi.Authority) *httpapi.Enforcer {
	t.Helper()
	built, err := httpapi.NewEnforcer(p, a, 60*time.Second)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	return built
}

// TestAnAppliedRevocationIsEnforcedForEveryClass is the property Proof A exists to
// demonstrate. A revocation that reached the projection refuses the operation regardless of
// class and regardless of freshness — freshness only decides what happens when the answer is
// absent, never when it is present.
func TestAnAppliedRevocationIsEnforcedForEveryClass(t *testing.T) {
	stub := stubProjection{
		age:    time.Second,
		record: projection.Record{MembershipID: membership(t), Status: projection.Revoked, Version: 7},
	}

	for _, class := range []httpapi.Class{httpapi.LowRisk, httpapi.HighConfidentiality} {
		decision, err := enforcer(t, stub, nil).Decide(context.Background(), class, membership(t), membership(t))
		if err != nil {
			t.Fatalf("%s: Decide: %v", class, err)
		}
		if decision.Allow {
			t.Errorf("%s: allowed an operation for a revoked membership", class)
		}
	}
}

// TestHighConfidentialityToleratesNoStaleness is the correction the principal review demanded.
//
// The class declared fail_closed and then read LOW_RISK's configured window, so a
// thirty-second-old projection with no recorded revocation served confidential data. Its budget is
// now its own and it is zero, which means a projection is never a sufficient answer for it -- at
// any age.
//
// Note what that exposes rather than hides: while this consumer projects only revocations, absence
// of a row is not positive authority, so HIGH_CONFIDENTIALITY refuses everything. That is the
// honest consequence of two facts the review named together, and it changes when the projection
// holds positive membership state.
func TestHighConfidentialityToleratesNoStaleness(t *testing.T) {
	for _, age := range []time.Duration{0, time.Second, 30 * time.Second, 10 * time.Minute} {
		stub := stubProjection{age: age, lookupErr: projection.ErrNotProjected}

		decision, err := enforcer(t, stub, nil).Decide(context.Background(),
			httpapi.HighConfidentiality, membership(t), membership(t))
		if err != nil {
			t.Fatalf("age %s: Decide: %v", age, err)
		}
		if decision.Allow {
			t.Errorf("age %s: HIGH_CONFIDENTIALITY was served from a projection", age)
		}
	}
}

// TestABrokenReadNeverFailsOpen separates "the projection is behind" from "the projection
// cannot be read". Fail-open exists for the first. Applying it to the second would turn a
// database fault into an authorisation bypass, on the class where bypass is cheapest to
// reach.
func TestABrokenReadNeverFailsOpen(t *testing.T) {
	broken := stubProjection{age: time.Second, lookupErr: errors.New("connection reset by peer")}

	for _, class := range []httpapi.Class{httpapi.LowRisk, httpapi.HighConfidentiality} {
		decision, err := enforcer(t, broken, nil).Decide(context.Background(), class, membership(t), membership(t))
		if err == nil {
			t.Errorf("%s: a broken read returned no error", class)
		}
		if decision.Allow {
			t.Errorf("%s: a broken read failed open", class)
		}
	}
}

// TestPrivilegedClassesNeverReadTheProjection is the assertion behind the review's point
// that an irreversible effect must not be authorised by a replica permitted to lag. The
// projection here says "revoked", and the authority says valid: the answer must come from
// the authority, so it must be an allow.
func TestPrivilegedClassesNeverReadTheProjection(t *testing.T) {
	contradicting := stubProjection{
		age:    time.Second,
		record: projection.Record{MembershipID: membership(t), Status: projection.Revoked, Version: 9},
	}
	authority := stubAuthority{granted: true}

	for _, class := range []httpapi.Class{httpapi.Privileged, httpapi.Irreversible} {
		decision, err := enforcer(t, contradicting, authority).Decide(context.Background(), class, membership(t), membership(t))
		if err != nil {
			t.Fatalf("%s: Decide: %v", class, err)
		}
		if !decision.Allow {
			t.Errorf("%s: refused despite the authority confirming validity, so it read the projection", class)
		}
	}
}

func TestAnUnreachableAuthorityRefusesRatherThanFallingBack(t *testing.T) {
	// The projection would allow this: nothing revoked, and fresh. Falling back to it would
	// make the classes that exist to avoid the replica depend on it precisely when the
	// estate is degraded.
	permissive := stubProjection{age: time.Second, lookupErr: projection.ErrNotProjected}
	unreachable := stubAuthority{err: errors.New("dial tcp: connection refused")}

	decision, err := enforcer(t, permissive, unreachable).Decide(context.Background(), httpapi.Privileged, membership(t), membership(t))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if decision.Allow {
		t.Error("an unreachable authority fell back to the projection")
	}
}

func TestAMissingAuthorityRefusesThePrivilegedClasses(t *testing.T) {
	permissive := stubProjection{age: time.Second, lookupErr: projection.ErrNotProjected}

	decision, err := enforcer(t, permissive, nil).Decide(context.Background(), httpapi.Irreversible, membership(t), membership(t))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if decision.Allow {
		t.Error("IRREVERSIBLE was allowed with no authority configured")
	}
}

// TestAConsumerThatNeverBootstrappedRefusesEverything is the invariant that replaced the cold-
// projection case, and it is sound where the old one was not.
//
// A consumer with no snapshot holds a model containing everything since it connected and nothing
// before. It has no positive authority for anyone, so no class may serve from it -- including the
// class that otherwise fails open, because fail-open is for an answer that may be out of date, not
// for having no answer at all.
func TestAConsumerThatNeverBootstrappedRefusesEverything(t *testing.T) {
	unbootstrapped := stubProjection{ageErr: projection.ErrNotBootstrapped, lookupErr: projection.ErrNotProjected}

	for _, class := range []httpapi.Class{httpapi.LowRisk, httpapi.HighConfidentiality} {
		decision, err := enforcer(t, unbootstrapped, nil).Decide(context.Background(),
			class, membership(t), membership(t))
		if err != nil {
			t.Fatalf("%s: Decide: %v", class, err)
		}
		if decision.Allow {
			t.Errorf("%s: a consumer that never bootstrapped served a request", class)
		}
	}
}

// TestAnAbsentMembershipIsRefusedForEveryClass is the principal review's first P0, as an assertion.
//
// Absence of a projected membership is not permission. Before this, an absent row meant either "holds
// an active membership" and "was never a member", and the consumer allowed both -- so "allowed" meant
// no bad news had arrived rather than authority being present.
func TestAnAbsentMembershipIsRefusedForEveryClass(t *testing.T) {
	fresh := stubProjection{age: time.Second, lookupErr: projection.ErrNotProjected}

	for _, class := range []httpapi.Class{httpapi.LowRisk, httpapi.HighConfidentiality} {
		decision, err := enforcer(t, fresh, nil).Decide(context.Background(),
			class, membership(t), membership(t))
		if err != nil {
			t.Fatalf("%s: Decide: %v", class, err)
		}
		if decision.Allow {
			t.Errorf("%s: allowed an operation with no projected membership", class)
		}
	}
}

// TestAnActiveMembershipIsAllowedWithinTheWindow is the other half, and it must be asserted too: a
// model that refuses everything is trivially safe and useless.
func TestAnActiveMembershipIsAllowedWithinTheWindow(t *testing.T) {
	active := stubProjection{
		age:    time.Second,
		record: projection.Record{MembershipID: membership(t), Status: projection.Active, Version: 3},
	}

	decision, err := enforcer(t, active, nil).Decide(context.Background(),
		httpapi.LowRisk, membership(t), membership(t))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !decision.Allow {
		t.Errorf("an active membership inside the window was refused: %s", decision.Reason)
	}
}

// TestASuspendedMembershipIsRefused keeps the third status from being treated as active. It arrives
// on a security event and it is a withdrawal, not a lifecycle detail.
func TestASuspendedMembershipIsRefused(t *testing.T) {
	suspended := stubProjection{
		age:    time.Second,
		record: projection.Record{MembershipID: membership(t), Status: projection.Suspended, Version: 4},
	}

	decision, err := enforcer(t, suspended, nil).Decide(context.Background(),
		httpapi.LowRisk, membership(t), membership(t))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if decision.Allow {
		t.Error("a suspended membership was served")
	}
}

// TestLowRiskServesAStaleActiveAnswerAndMarksIt is what fail-open means under the positive-authority
// model, and it is narrower than what it meant before.
//
// Fail-open applies to a positive answer that may be out of date -- an active membership whose
// revocation might be in flight. It does NOT apply to the absence of an answer, which is now a
// refusal for every class. The old test asserted the opposite, and it was asserting the defect.
func TestLowRiskServesAStaleActiveAnswerAndMarksIt(t *testing.T) {
	active := projection.Record{MembershipID: membership(t), Status: projection.Active, Version: 3}

	within, err := enforcer(t, stubProjection{age: 30 * time.Second, record: active}, nil).
		Decide(context.Background(), httpapi.LowRisk, membership(t), membership(t))
	if err != nil {
		t.Fatalf("Decide inside the window: %v", err)
	}
	if !within.Allow || within.Stale {
		t.Errorf("active inside the window: allow = %v, stale = %v, want true and false",
			within.Allow, within.Stale)
	}

	past, err := enforcer(t, stubProjection{age: 10 * time.Minute, record: active}, nil).
		Decide(context.Background(), httpapi.LowRisk, membership(t), membership(t))
	if err != nil {
		t.Fatalf("Decide past the window: %v", err)
	}
	if !past.Allow {
		t.Errorf("LOW_RISK refused a stale active membership; this class fails open: %s", past.Reason)
	}
	// The allow is the designed behaviour; the flag is what makes it visible. An allow-while-stale
	// reporting stale = false is an outage nobody can see.
	if !past.Stale {
		t.Error("a stale active answer was served without being marked stale")
	}
}

// TestHighConfidentialityRefusesAStaleActiveAnswer is the same case on the class that tolerates
// nothing: an active membership is not enough, because its withdrawal may be in flight.
func TestHighConfidentialityRefusesAStaleActiveAnswer(t *testing.T) {
	active := projection.Record{MembershipID: membership(t), Status: projection.Active, Version: 3}

	decision, err := enforcer(t, stubProjection{age: time.Second, record: active}, nil).
		Decide(context.Background(), httpapi.HighConfidentiality, membership(t), membership(t))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if decision.Allow {
		t.Error("HIGH_CONFIDENTIALITY served an active membership from the projection")
	}
}
