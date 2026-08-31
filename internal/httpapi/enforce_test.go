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

func (s stubProjection) Lookup(context.Context, id.UUID) (projection.Record, error) {
	return s.record, s.lookupErr
}

type stubAuthority struct {
	valid bool
	err   error
}

func (s stubAuthority) MembershipValid(context.Context, id.UUID) (bool, error) {
	return s.valid, s.err
}

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
		record: projection.Record{MembershipID: membership(t), Revoked: true, Version: 7},
	}

	for _, class := range []httpapi.Class{httpapi.LowRisk, httpapi.HighConfidentiality} {
		decision, err := enforcer(t, stub, nil).Decide(context.Background(), class, membership(t))
		if err != nil {
			t.Fatalf("%s: Decide: %v", class, err)
		}
		if decision.Allow {
			t.Errorf("%s: allowed an operation for a revoked membership", class)
		}
	}
}

func TestLowRiskFailsOpenOnlyWithinTheBound(t *testing.T) {
	fresh := stubProjection{age: 30 * time.Second, lookupErr: projection.ErrNotProjected}
	stale := stubProjection{age: 10 * time.Minute, lookupErr: projection.ErrNotProjected}

	within, err := enforcer(t, fresh, nil).Decide(context.Background(), httpapi.LowRisk, membership(t))
	if err != nil {
		t.Fatalf("Decide within the bound: %v", err)
	}
	if !within.Allow || within.Stale {
		t.Errorf("a fresh projection with no revocation: allow = %v, stale = %v, want true and false",
			within.Allow, within.Stale)
	}

	past, err := enforcer(t, stale, nil).Decide(context.Background(), httpapi.LowRisk, membership(t))
	if err != nil {
		t.Fatalf("Decide past the bound: %v", err)
	}
	if !past.Allow {
		t.Error("LOW_RISK past the bound was refused; this class fails open by design")
	}
	// The allow is the designed behaviour; the flag is what makes it visible. An
	// allow-while-stale that reports stale = false is an outage nobody can see.
	if !past.Stale {
		t.Error("LOW_RISK served from a stale projection did not report stale")
	}
}

func TestHighConfidentialityFailsClosedPastTheBound(t *testing.T) {
	stale := stubProjection{age: 10 * time.Minute, lookupErr: projection.ErrNotProjected}

	decision, err := enforcer(t, stale, nil).Decide(context.Background(), httpapi.HighConfidentiality, membership(t))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if decision.Allow {
		t.Error("HIGH_CONFIDENTIALITY was served from a projection past its bound")
	}
}

// TestABrokenReadNeverFailsOpen separates "the projection is behind" from "the projection
// cannot be read". Fail-open exists for the first. Applying it to the second would turn a
// database fault into an authorisation bypass, on the class where bypass is cheapest to
// reach.
func TestABrokenReadNeverFailsOpen(t *testing.T) {
	broken := stubProjection{age: time.Second, lookupErr: errors.New("connection reset by peer")}

	for _, class := range []httpapi.Class{httpapi.LowRisk, httpapi.HighConfidentiality} {
		decision, err := enforcer(t, broken, nil).Decide(context.Background(), class, membership(t))
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
		record: projection.Record{MembershipID: membership(t), Revoked: true, Version: 9},
	}
	authority := stubAuthority{valid: true}

	for _, class := range []httpapi.Class{httpapi.Privileged, httpapi.Irreversible} {
		decision, err := enforcer(t, contradicting, authority).Decide(context.Background(), class, membership(t))
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

	decision, err := enforcer(t, permissive, unreachable).Decide(context.Background(), httpapi.Privileged, membership(t))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if decision.Allow {
		t.Error("an unreachable authority fell back to the projection")
	}
}

func TestAMissingAuthorityRefusesThePrivilegedClasses(t *testing.T) {
	permissive := stubProjection{age: time.Second, lookupErr: projection.ErrNotProjected}

	decision, err := enforcer(t, permissive, nil).Decide(context.Background(), httpapi.Irreversible, membership(t))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if decision.Allow {
		t.Error("IRREVERSIBLE was allowed with no authority configured")
	}
}

func TestAColdProjectionFollowsTheClassPolicy(t *testing.T) {
	cold := stubProjection{ageErr: projection.ErrProjectionCold, lookupErr: projection.ErrProjectionCold}

	open, err := enforcer(t, cold, nil).Decide(context.Background(), httpapi.LowRisk, membership(t))
	if err != nil {
		t.Fatalf("Decide LOW_RISK: %v", err)
	}
	if !open.Allow {
		t.Error("LOW_RISK on a cold projection was refused; this class fails open")
	}

	closed, err := enforcer(t, cold, nil).Decide(context.Background(), httpapi.HighConfidentiality, membership(t))
	if err != nil {
		t.Fatalf("Decide HIGH_CONFIDENTIALITY: %v", err)
	}
	if closed.Allow {
		t.Error("HIGH_CONFIDENTIALITY on a cold projection was allowed")
	}
}
