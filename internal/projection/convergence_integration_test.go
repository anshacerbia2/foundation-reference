package projection_test

// Snapshot plus catch-up, with the authority changing in between.
//
// The principal review asked for exactly this, and organization-control's own test explains why it is
// not a formality: `platform.outbox.sequence` is allocated at INSERT, not at COMMIT, so a transaction
// can hold sequence N while a later one takes N+1 and commits first. A snapshot taken in between
// reports mark N+1 and does not see the row at N. A consumer told "discard everything at or below the
// mark" would discard the only event that would ever deliver it.
//
// So the contract this side must honour is: seed the snapshot at its mark, then apply every buffered
// event by VERSION comparison rather than by discarding at the mark. These cases assert that the
// consumer converges on the authority's state under the three shapes that arise:
//
//   - a membership whose state moved after page 1 was taken
//   - a membership created after page 1, returned by a later page as of a newer instant
//   - a membership absent from the snapshot entirely, delivered only as an event
//
// Paging is simulated rather than driven over HTTP: what is under test is the consumer's convergence
// rule, and organization-control's suite already asserts that every page of one snapshot carries one
// mark and that continuing without it is refused.

import (
	"testing"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/foundation-reference/internal/projection"
)

// authorityState is what the producer would report if asked directly, written down so the assertion
// compares the consumer against the authority rather than against itself.
type authorityState struct {
	membership projection.Status
	version    int64
}

func TestTheConsumerConvergesWhenTheAuthorityChangesMidSnapshot(t *testing.T) {
	projector, _, ctx := fixture(t)

	// Three principals in one tenant, each with one membership.
	stable := newSubject(t)   // untouched during the snapshot
	moved := newSubject(t)    // revoked between page 1 and page 2
	replaced := newSubject(t) // its principal is granted a second membership after page 1
	replacement := replaced
	replacement.membership = newID(t)
	late := newSubject(t) // absent from the snapshot; arrives only as an event

	const mark int64 = 1000

	// Page 1, taken at mark 1000: the state as of then.
	if err := projector.Seed(ctx, []projection.Seeded{
		{MembershipID: stable.membership, TenantID: stable.tenant, PrincipalID: stable.principal,
			Status: projection.Active, Version: 1},
		{MembershipID: moved.membership, TenantID: moved.tenant, PrincipalID: moved.principal,
			Status: projection.Active, Version: 1},
	}, mark, false); err != nil {
		t.Fatalf("seeding page 1: %v", err)
	}

	// The authority changes here, between the pages: `moved` is revoked, and `replaced` is granted a
	// second membership. Both happen after mark 1000.

	// Page 2, taken later but continuing the same snapshot, so it is seeded at the SAME mark. It
	// carries rows as of its own instant, which is the part that makes this awkward: `replaced` did
	// not exist at mark 1000 and appears here anyway.
	if err := projector.Seed(ctx, []projection.Seeded{
		{MembershipID: replaced.membership, TenantID: replaced.tenant, PrincipalID: replaced.principal,
			Status: projection.Active, Version: 1},
		{MembershipID: replacement.membership, TenantID: replacement.tenant, PrincipalID: replacement.principal,
			Status: projection.Active, Version: 1},
	}, mark, true); err != nil {
		t.Fatalf("seeding page 2: %v", err)
	}

	// Catch-up: every event after the mark, in the order the dispatcher happens to deliver them --
	// which is not necessarily the order the authority committed them.
	revocation := revoked(t, moved, 2)
	revocation.StreamPosition = 1001
	if _, err := projector.Apply(ctx, revocation); err != nil {
		t.Fatalf("replaying the revocation: %v", err)
	}

	// The grant for `replacement`, which page 2 already reported. Applying it must not regress
	// anything: it carries version 1 against a seeded version 1, so it is superseded rather than
	// re-applied, and that is the case a consumer discarding at the mark would get wrong in the
	// opposite direction.
	duplicateGrant := granted(t, replacement, 1)
	duplicateGrant.StreamPosition = 1002
	outcome, err := projector.Apply(ctx, duplicateGrant)
	if err != nil {
		t.Fatalf("replaying a grant the snapshot already carried: %v", err)
	}
	if outcome.Applied {
		t.Error("an event at the version the snapshot already held was applied again")
	}

	// The membership the snapshot never saw. This is the in-flight case: it was uncommitted when the
	// mark was taken, so it is in neither page, and only the event delivers it.
	lateGrant := granted(t, late, 1)
	lateGrant.StreamPosition = 1003
	if _, err := projector.Apply(ctx, lateGrant); err != nil {
		t.Fatalf("replaying the late grant: %v", err)
	}

	// Now compare the consumer against the authority, membership by membership.
	want := map[string]authorityState{
		stable.membership.String():      {projection.Active, 1},
		moved.membership.String():       {projection.Revoked, 2},
		replaced.membership.String():    {projection.Active, 1},
		replacement.membership.String(): {projection.Active, 1},
		late.membership.String():        {projection.Active, 1},
	}

	for membershipID, expected := range want {
		parsed, err := id.Parse(membershipID)
		if err != nil {
			t.Fatalf("parsing %s: %v", membershipID, err)
		}
		record, err := projector.LookupMembership(ctx, parsed)
		if err != nil {
			t.Errorf("membership %s is not projected: %v", membershipID, err)
			continue
		}
		if record.Status != expected.membership || record.Version != expected.version {
			t.Errorf("membership %s projected as %s v%d, authority has %s v%d",
				membershipID, record.Status, record.Version, expected.membership, expected.version)
		}
	}

	// And the enforcement answer, which is what any of this is for.
	if _, err := projector.Lookup(ctx, moved.tenant, moved.principal); err == nil {
		t.Error("the revoked principal still holds an active membership after catch-up")
	}
	if _, err := projector.Lookup(ctx, late.tenant, late.principal); err != nil {
		t.Errorf("the principal delivered only by an event holds no authority: %v", err)
	}
	if _, err := projector.Lookup(ctx, stable.tenant, stable.principal); err != nil {
		t.Errorf("the untouched principal lost its authority across the snapshot: %v", err)
	}
}

// TestCatchUpDoesNotRegressStateThePagesAlreadyCarried is the failure mode of the opposite mistake:
// applying buffered events unconditionally rather than by version.
//
// Page 2 is taken after the authority revoked a membership, so it carries the revocation. The
// buffered grant from before it — which is still below the page's state but above the mark — must not
// bring the membership back.
func TestCatchUpDoesNotRegressStateThePagesAlreadyCarried(t *testing.T) {
	projector, _, ctx := fixture(t)
	subject := newSubject(t)
	const mark int64 = 2000

	// The snapshot page carries the state as of a later instant: already revoked at version 2.
	if err := projector.Seed(ctx, []projection.Seeded{{
		MembershipID: subject.membership,
		TenantID:     subject.tenant,
		PrincipalID:  subject.principal,
		Status:       projection.Revoked,
		Version:      2,
	}}, mark, true); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	// A buffered event from before that revocation, delivered after the snapshot.
	stale := granted(t, subject, 1)
	stale.StreamPosition = 2001
	outcome, err := projector.Apply(ctx, stale)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if outcome.Applied {
		t.Error("a buffered grant older than the snapshot's state was applied")
	}

	record, err := projector.LookupMembership(ctx, subject.membership)
	if err != nil {
		t.Fatalf("LookupMembership: %v", err)
	}
	if record.Status != projection.Revoked || record.Version != 2 {
		t.Errorf("state regressed to %s v%d; catch-up reinstated a revoked membership",
			record.Status, record.Version)
	}
	if _, err := projector.Lookup(ctx, subject.tenant, subject.principal); err == nil {
		t.Error("a revoked principal holds an active membership after catch-up")
	}
}
