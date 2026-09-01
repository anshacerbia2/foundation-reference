package httpapi_test

// The fail-open/fail-closed policy is the decision the principal review called the most
// important one in the whole slice, and a policy that lives only in a table is a policy that
// changes without anyone noticing. These tests are what make it invariant: each one fails if
// a class's behaviour is edited.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-reference/internal/frontier"

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

// stubFrontier is a producer that owes nothing unless told otherwise, so the existing cases keep
// asserting what they were written to assert.
type stubFrontier struct {
	facts frontier.Facts
	err   error
}

func (s stubFrontier) Frontier(context.Context) (frontier.Facts, error) {
	return s.facts, s.err
}

// current is a producer with nothing owed, observed just now.
func current() stubFrontier {
	return stubFrontier{facts: frontier.Facts{
		HighestCommittedMark: 100,
		ObservedAt:           time.Now().UTC(),
		ReadAt:               time.Now().UTC(),
	}}
}

func enforcer(t *testing.T, p httpapi.Projection, a httpapi.Authority) *httpapi.Enforcer {
	t.Helper()
	return enforcerWith(t, p, a, current())
}

func enforcerWith(t *testing.T, p httpapi.Projection, a httpapi.Authority, f httpapi.Frontier) *httpapi.Enforcer {
	t.Helper()
	built, err := httpapi.NewEnforcer(p, a, f, 60*time.Second)
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
	// The revocation has arrived, so Lookup reports that no active membership remains for the pair.
	// Under the EXISTS-active contract that is ErrWithdrawn, not a record carrying a revoked status:
	// several memberships may exist and enforcement asks whether any of them is active.
	stub := stubProjection{age: time.Second, lookupErr: projection.ErrWithdrawn}

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

// TestAWithdrawnPairIsRefusedAndDistinguishedFromAnUnknownOne keeps the two refusals apart. Both
// deny, and an operator reading one needs to know whether this consumer has ever seen the principal.
func TestAWithdrawnPairIsRefusedAndDistinguishedFromAnUnknownOne(t *testing.T) {
	withdrawn := stubProjection{age: time.Second, lookupErr: projection.ErrWithdrawn}
	unknown := stubProjection{age: time.Second, lookupErr: projection.ErrNotProjected}

	first, err := enforcer(t, withdrawn, nil).Decide(context.Background(),
		httpapi.LowRisk, membership(t), membership(t))
	if err != nil {
		t.Fatalf("Decide on a withdrawn pair: %v", err)
	}
	second, err := enforcer(t, unknown, nil).Decide(context.Background(),
		httpapi.LowRisk, membership(t), membership(t))
	if err != nil {
		t.Fatalf("Decide on an unknown pair: %v", err)
	}

	if first.Allow || second.Allow {
		t.Fatalf("a refusal was expected for both: withdrawn = %v, unknown = %v", first.Allow, second.Allow)
	}
	if first.Reason == second.Reason {
		t.Errorf("both refusals read %q; a withdrawal and an unknown principal must be distinguishable", first.Reason)
	}
}

// TestAProducerBehindItsBudgetMakesTheConsumerStale is the term only the producer can supply.
//
// The projection is young and holds an active membership, so every local signal says fresh. The
// producer has owed a delivery for ten minutes, which the consumer cannot see: a gap below its own
// applied position is indistinguishable from a sequence number a rolled-back transaction consumed.
func TestAProducerBehindItsBudgetMakesTheConsumerStale(t *testing.T) {
	active := stubProjection{
		age:    time.Second,
		record: projection.Record{MembershipID: membership(t), Status: projection.Active, Version: 3},
	}
	behind := stubFrontier{facts: frontier.Facts{
		HighestCommittedMark:  120,
		OldestUnpublishedMark: 90,
		OldestUnpublishedAge:  10 * time.Minute,
		Unpublished:           true,
		ObservedAt:            time.Now().UTC(),
		ReadAt:                time.Now().UTC(),
	}}

	// LOW_RISK fails open, so it serves -- and must say it is stale.
	low, err := enforcerWith(t, active, nil, behind).Decide(context.Background(),
		httpapi.LowRisk, membership(t), membership(t))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !low.Stale {
		t.Error("a producer ten minutes behind did not make the answer stale")
	}
	if low.Reason == "" || !contains(low.Reason, "owed") {
		t.Errorf("the reason does not name the producer's backlog: %q", low.Reason)
	}
}

// TestAnUnreachableFrontierIsStaleRatherThanFine keeps "unknown" apart from "nothing owed".
func TestAnUnreachableFrontierIsStaleRatherThanFine(t *testing.T) {
	active := stubProjection{
		age:    time.Second,
		record: projection.Record{MembershipID: membership(t), Status: projection.Active, Version: 3},
	}
	unreachable := stubFrontier{err: errors.New("dial tcp: connection refused")}

	decision, err := enforcerWith(t, active, nil, unreachable).Decide(context.Background(),
		httpapi.LowRisk, membership(t), membership(t))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !decision.Stale {
		t.Error("an unreachable frontier was treated as a producer that owes nothing")
	}
}

// TestNoFrontierConfiguredIsStale states the cost of leaving it out, rather than defaulting to fresh.
func TestNoFrontierConfiguredIsStale(t *testing.T) {
	active := stubProjection{
		age:    time.Second,
		record: projection.Record{MembershipID: membership(t), Status: projection.Active, Version: 3},
	}

	decision, err := enforcerWith(t, active, nil, nil).Decide(context.Background(),
		httpapi.LowRisk, membership(t), membership(t))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !decision.Stale {
		t.Error("a consumer with no frontier certified itself fresh")
	}
}

// TestACachedFrontierAgesRatherThanFreezing covers the arithmetic that a cache makes tempting to
// skip: the producer observed its backlog at an instant that has passed, so the age it reported has
// grown since.
func TestACachedFrontierAgesRatherThanFreezing(t *testing.T) {
	active := stubProjection{
		age:    time.Second,
		record: projection.Record{MembershipID: membership(t), Status: projection.Active, Version: 3},
	}
	// Owed for 40s as observed 40s ago: 80s in total, past the 60s window.
	observed := time.Now().UTC().Add(-40 * time.Second)
	stale := stubFrontier{facts: frontier.Facts{
		OldestUnpublishedAge: 40 * time.Second,
		Unpublished:          true,
		ObservedAt:           observed,
		ReadAt:               observed,
	}}

	decision, err := enforcerWith(t, active, nil, stale).Decide(context.Background(),
		httpapi.LowRisk, membership(t), membership(t))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !decision.Stale {
		t.Error("a frontier observed 40s ago reporting a 40s backlog was treated as inside a 60s window")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && strings.Contains(haystack, needle)
}
