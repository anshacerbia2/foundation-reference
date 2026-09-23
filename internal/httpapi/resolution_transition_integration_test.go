package httpapi_test

// The A/B proof: what resolving the producer's debt actually restores, and what it must not.
//
// Every other case in this package drives the enforcer against a stubbed projection, which is the
// right tool for the freshness branches -- a producer that owes an old delivery cannot be arranged
// against a healthy database. It is the wrong tool for this one. The question here is whether a
// revocation that was DELIVERED and APPLIED still refuses after the incident that delayed it is
// closed, and a stub asserting "Lookup says withdrawn" answers that question with its own premise.
//
// So the projection is real, on a real PostgreSQL, and the two principals differ only in what was
// delivered about them:
//
//	A  granted, then revoked -- the revocation this estate exists to enforce
//	B  granted               -- an ordinary active membership, collateral to A's incident
//
// The only stub is the producer's frontier facts, because that side's behaviour is proven in
// organization-control's own suite and cannot be driven from here.
//
// # Why "both refused" is not the assertion
//
// While the debt stands, A and B are both refused, and that is the correct behaviour. But a test
// that asserted only that would pass in an estate where the revocation never arrived at all: an
// unapplied revocation and an applied one look identical for as long as everything is refused.
//
// The assertion is therefore what resolution SEPARATES. B flips to allowed and A does not, from the
// same act. If the revocation had never landed, A would be allowed in the second phase alongside B.
//
// A's refusal reason does not move, and that is worth stating because it is not what this proof was
// planned to show. The enforcer answers "no active membership" ahead of any freshness question, so
// an applied revocation never needed the producer to be current before it was enforced. What the
// debt changes for A is the Stale marker -- what this consumer can vouch for, not what it knows.

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/event"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/foundation-reference/internal/frontier"
	"github.com/anshacerbia2/foundation-reference/internal/httpapi"
	"github.com/anshacerbia2/foundation-reference/internal/projection"
)

const producer event.Source = "//scnehaux.com/organization-control"

// principal is one (Tenant, Principal, Membership) triple. Held together because enforcement asks
// about the pair while the event carries all three.
type principal struct {
	tenant     id.UUID
	principal  id.UUID
	membership id.UUID
}

func newPrincipal(t *testing.T) principal {
	t.Helper()
	return principal{tenant: mint(t), principal: mint(t), membership: mint(t)}
}

func mint(t *testing.T) id.UUID {
	t.Helper()
	minted, err := id.NewV7()
	if err != nil {
		t.Fatalf("minting an identifier: %v", err)
	}
	return minted
}

// realProjection is this consumer's own projection, against the engine rather than a fake.
//
// The consumer name is unique per test and per run because the inbox deduplicates per
// (event_id, consumer), and a name reused across runs would make a second run's deliveries look
// like duplicates of the first.
func realProjection(t *testing.T) (*projection.Projector, context.Context) {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_INTEGRATION") != "" {
			t.Fatal("REQUIRE_INTEGRATION is set and TEST_DATABASE_URL is empty: the database this " +
				"proof asserts against never came up")
		}
		t.Skip("TEST_DATABASE_URL is unset")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	pool, err := db.Open(ctx, db.Config{Name: "transition-test", DSN: dsn, MaxConns: 4})
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)

	projector, err := projection.New(pool, "test-"+t.Name()+"-"+mint(t).String())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return projector, ctx
}

// applyDelivery applies one event the way the dispatcher would, and fails the test if it did not land.
//
// position is the producer's stream position, which orders a delivery against the snapshot and
// against other memberships for the same pair. Below the snapshot mark it would be discarded as
// older than the bootstrap, which is a silent no-op -- and a proof resting on a delivery that
// silently did nothing proves the opposite of what it claims.
func applyDelivery(t *testing.T, projector *projection.Projector, ctx context.Context,
	who principal, typ event.Type, status string, version, position int64) {
	t.Helper()

	envelope, err := event.New(producer, typ, time.Now().UTC(), projection.Payload{
		MembershipID: who.membership,
		TenantID:     who.tenant,
		PrincipalID:  who.principal,
		Version:      version,
		Status:       status,
	})
	if err != nil {
		t.Fatalf("building an envelope: %v", err)
	}
	envelope.StreamPosition = position

	if _, err := projector.Apply(ctx, envelope); err != nil {
		t.Fatalf("applying %s at position %d: %v", typ, position, err)
	}
}

// indebted is a producer that has given up on an authority-bearing delivery.
func indebted() stubFrontier {
	return stubFrontier{facts: frontier.Facts{
		HighestCommittedMark:        100,
		SecurityDebt:                true,
		SecurityDeadLettered:        1,
		OldestSecurityDeadLetterAge: 48 * time.Hour,
		ObservedAt:                  time.Now().UTC(),
		ReadAt:                      time.Now().UTC(),
	}}
}

func TestResolvingTheDebtRestoresTheBystanderAndLeavesTheRevocationEnforced(t *testing.T) {
	projector, ctx := realProjection(t)

	// Bootstrapped first, the way a consumer joins: a snapshot at a mark, then live deliveries
	// after it. Without this the enforcer refuses everything for a sound reason of its own
	// (ErrNotBootstrapped) and the phases below would be indistinguishable.
	bystanderSeed := newPrincipal(t)
	if err := projector.Seed(ctx, []projection.Seeded{{
		MembershipID: bystanderSeed.membership,
		TenantID:     bystanderSeed.tenant,
		PrincipalID:  bystanderSeed.principal,
		Status:       projection.Active,
		Version:      1,
	}}, 1000, true); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	a, b := newPrincipal(t), newPrincipal(t)
	applyDelivery(t, projector, ctx, a, projection.MembershipGranted, "active", 1, 1001)
	applyDelivery(t, projector, ctx, a, projection.MembershipRevoked, "revoked", 2, 1002)
	applyDelivery(t, projector, ctx, b, projection.MembershipGranted, "active", 1, 1003)

	// The premise, checked rather than assumed. If the revocation had not applied, every assertion
	// below would still read plausibly while proving nothing.
	if _, err := projector.Lookup(ctx, a.tenant, a.principal); !errors.Is(err, projection.ErrWithdrawn) {
		t.Fatalf("A's revocation did not land: Lookup returned %v, want ErrWithdrawn", err)
	}
	if _, err := projector.Lookup(ctx, b.tenant, b.principal); err != nil {
		t.Fatalf("B holds no active membership: %v", err)
	}

	// Phase one: the producer has given up on an authority-bearing delivery.
	debted := enforcerWith(t, projector, nil, indebted())

	refusedA, err := debted.Decide(ctx, httpapi.LowRisk, a.tenant, a.principal)
	if err != nil {
		t.Fatalf("Decide for A under debt: %v", err)
	}
	refusedB, err := debted.Decide(ctx, httpapi.LowRisk, b.tenant, b.principal)
	if err != nil {
		t.Fatalf("Decide for B under debt: %v", err)
	}
	if refusedA.Allow || refusedB.Allow {
		t.Fatalf("the producer's debt did not refuse both principals: A allowed=%v, B allowed=%v",
			refusedA.Allow, refusedB.Allow)
	}
	// B is refused for a reason that has nothing to do with B. That is the cost the debt imposes,
	// and naming it is what makes the second phase a restoration rather than a coincidence.
	if !strings.Contains(refusedB.Reason, "given up on") {
		t.Errorf("B is refused for a reason other than the producer's debt: %q", refusedB.Reason)
	}
	// A is refused for the withdrawal, NOT for the debt, and this is where the estate's actual
	// behaviour differs from the shape this proof was planned in.
	//
	// The plan expected A's refusal reason to move from the debt to the withdrawal once the
	// incident closed. It does not, because the enforcer answers "no active membership" ahead of
	// any freshness question: a withdrawal that has arrived is not made less true by the producer's
	// lag. The debt changes what this consumer can VOUCH for, which is the Stale marker below, not
	// what it knows about A. Bending the enforcer to produce the planned transition would have made
	// a revocation's enforcement depend on the producer's publication state, which is the inversion
	// this whole contract exists to prevent -- so the assertion moved instead.
	if !strings.Contains(refusedA.Reason, "no active membership") {
		t.Errorf("A is refused for %q while the debt stands, want the withdrawal itself: an applied "+
			"revocation must not need the producer to be current before it is enforced", refusedA.Reason)
	}
	if !refusedA.Stale {
		t.Error("A's refusal is not marked stale while the producer holds an authority-bearing " +
			"dead letter; the operator loses the signal that this consumer cannot vouch for its model")
	}

	// Phase two: an operator resolved the incident on applied evidence, so the producer reports no
	// debt. Nothing about either principal's membership changed.
	resolved := enforcerWith(t, projector, nil, current())

	servedB, err := resolved.Decide(ctx, httpapi.LowRisk, b.tenant, b.principal)
	if err != nil {
		t.Fatalf("Decide for B after resolution: %v", err)
	}
	if !servedB.Allow {
		t.Errorf("B is still refused after the debt was resolved: %q\n"+
			"Resolution that does not restore service for an uninvolved principal leaves the estate "+
			"exactly as stuck as the incident left it.", servedB.Reason)
	}

	stillRefusedA, err := resolved.Decide(ctx, httpapi.LowRisk, a.tenant, a.principal)
	if err != nil {
		t.Fatalf("Decide for A after resolution: %v", err)
	}
	if stillRefusedA.Allow {
		t.Fatal("A is allowed after the debt was resolved: closing the incident released the " +
			"revocation it was delaying, which is the failure this whole contract exists to prevent")
	}

	// A is refused for the same reason as before, and that sameness is the property rather than a
	// weakness: the ground for refusing A never depended on the producer's publication state.
	if !strings.Contains(stillRefusedA.Reason, "no active membership") {
		t.Errorf("A is refused for %q, want the withdrawal itself", stillRefusedA.Reason)
	}
	// What did change is what this consumer can vouch for. While the debt stood, every answer it
	// gave was marked stale; with the debt resolved, A's refusal is a plain statement about A. An
	// operator paging on staleness would otherwise be paged for the system working.
	if stillRefusedA.Stale {
		t.Errorf("A's refusal is still marked stale after the debt was resolved: %q", stillRefusedA.Reason)
	}
	if !refusedA.Stale || stillRefusedA.Stale {
		t.Errorf("the debt marker did not move: stale under debt = %v, stale after resolution = %v",
			refusedA.Stale, stillRefusedA.Stale)
	}

	// The whole proof in one line. B moved and A did not, from the same resolution -- which is
	// what separates "the incident was closed" from "the revocation was released along with it".
	// A test asserting only that both stayed refused would pass in an estate where the revocation
	// never arrived at all, because B's restoration is the only thing that distinguishes the two.
	if !servedB.Allow || stillRefusedA.Allow {
		t.Fatalf("resolution did not separate the two principals: B allowed=%v, A allowed=%v",
			servedB.Allow, stillRefusedA.Allow)
	}
}
