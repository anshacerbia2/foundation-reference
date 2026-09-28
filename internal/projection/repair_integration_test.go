package projection_test

// Reconciliation repairs, applied (organization-control ROADMAP item 19).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/event"

	"github.com/anshacerbia2/foundation-reference/internal/projection"
)

func stateOf(s subject, version int64, status string) *projection.Payload {
	return &projection.Payload{MembershipID: s.membership, TenantID: s.tenant, PrincipalID: s.principal,
		Version: version, Status: status}
}

func repairEnvelope(t *testing.T, consumer string, position int64, findings ...projection.RepairFinding) event.Envelope {
	t.Helper()
	envelope, err := event.New(source, projection.RepairReconciled, time.Now().UTC(), projection.RepairPayload{
		ConsumerID: consumer, Mark: position, Findings: findings,
	})
	if err != nil {
		t.Fatalf("building a repair envelope: %v", err)
	}
	envelope.StreamPosition = position
	return envelope
}

// A sweep repairs all three ways at once: a Membership the consumer lacks is added, one authority has
// revoked is withdrawn, and one authority never granted is removed.
func TestARepairAddsWithdrawsAndRemoves(t *testing.T) {
	projector, _, ctx, consumer := fixtureNamed(t)

	missing, withdrawn, invented := newSubject(t), newSubject(t), newSubject(t)
	for _, s := range []subject{withdrawn, invented} {
		if _, err := projector.Apply(ctx, granted(t, s, 1)); err != nil {
			t.Fatalf("Apply: %v", err)
		}
	}

	outcome, err := projector.Apply(ctx, repairEnvelope(t, consumer, 50,
		projection.RepairFinding{Classification: "missing", MembershipID: missing.membership, State: stateOf(missing, 3, "active")},
		projection.RepairFinding{Classification: "extra", MembershipID: withdrawn.membership, State: stateOf(withdrawn, 2, "revoked")},
		projection.RepairFinding{Classification: "extra", MembershipID: invented.membership, State: nil},
	))
	if err != nil {
		t.Fatalf("Apply(repair): %v", err)
	}
	if !outcome.Applied || outcome.Acknowledged {
		t.Fatalf("outcome = %+v, want applied", outcome)
	}

	if record, err := projector.LookupMembership(ctx, missing.membership); err != nil || record.Status != projection.Active || record.Version != 3 {
		t.Errorf("the missing Membership is %+v (%v), want active at version 3", record, err)
	}
	if record, err := projector.LookupMembership(ctx, withdrawn.membership); err != nil || record.Status != projection.Revoked || record.Version != 2 {
		t.Errorf("the withdrawn Membership is %+v (%v), want revoked at version 2", record, err)
	}
	if _, err := projector.LookupMembership(ctx, invented.membership); err == nil {
		t.Error("the Membership authority never granted is still projected")
	}
}

// The version rule holds for repairs as for events: a sweep older than what the consumer holds changes
// nothing, so a delayed repair cannot resurrect a revoked Membership.
func TestARepairNeverRollsANewerStateBack(t *testing.T) {
	projector, _, ctx, consumer := fixtureNamed(t)
	s := newSubject(t)
	if _, err := projector.Apply(ctx, revoked(t, s, 5)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := projector.Apply(ctx, repairEnvelope(t, consumer, 60,
		projection.RepairFinding{Classification: "mismatch", MembershipID: s.membership, State: stateOf(s, 3, "active")},
	)); err != nil {
		t.Fatalf("Apply(repair): %v", err)
	}
	if record, _ := projector.LookupMembership(ctx, s.membership); record.Status != projection.Revoked || record.Version != 5 {
		t.Errorf("an older repair rolled the Membership back to %+v", record)
	}
}

// A sweep describes one consumer's report. Another consumer's findings are acknowledged, not applied.
func TestAnotherConsumersRepairIsAcknowledged(t *testing.T) {
	projector, _, ctx := fixture(t)
	s := newSubject(t)
	outcome, err := projector.Apply(ctx, repairEnvelope(t, "some-other-consumer", 70,
		projection.RepairFinding{Classification: "missing", MembershipID: s.membership, State: stateOf(s, 1, "active")},
	))
	if err != nil {
		t.Fatalf("Apply(repair): %v", err)
	}
	if !outcome.Acknowledged || outcome.Applied {
		t.Errorf("outcome = %+v, want acknowledged", outcome)
	}
	if _, err := projector.LookupMembership(ctx, s.membership); err == nil {
		t.Error("another consumer's repair was applied here")
	}
}

func TestAnIncoherentRepairIsRefused(t *testing.T) {
	projector, _, ctx, consumer := fixtureNamed(t)
	s, other := newSubject(t), newSubject(t)
	for name, finding := range map[string]projection.RepairFinding{
		"a state for another membership": {MembershipID: s.membership, State: stateOf(other, 1, "active")},
		"an unknown status":              {MembershipID: s.membership, State: stateOf(s, 1, "pending")},
		"no version":                     {MembershipID: s.membership, State: stateOf(s, 0, "active")},
		// What a producer from before the state sends. Its null must not read as "remove", or a
		// mismatch would delete a Membership authority holds.
		"a mismatch with no state": {Classification: "mismatch", MembershipID: s.membership},
		"a missing with no state":  {Classification: "missing", MembershipID: s.membership},
	} {
		if _, err := projector.Apply(context.Background(), repairEnvelope(t, consumer, 80, finding)); !errors.Is(err, projection.ErrMalformed) {
			t.Errorf("%s: Apply returned %v, want ErrMalformed", name, err)
		}
	}
	_ = ctx
}
