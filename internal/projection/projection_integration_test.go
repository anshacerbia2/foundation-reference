package projection_test

// The two properties this consumer rests on, proven against a real PostgreSQL rather than
// against a fake that would agree with whatever the code does:
//
//   - a duplicate delivery cannot apply an effect twice
//   - an out-of-order delivery cannot undo a newer one
//
// The second is the load-bearing one for the estate's broker choice. If it holds, per-key
// ordering stops being a correctness requirement and becomes a performance concern, and the
// broker can be selected on operational grounds.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/event"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/foundation-reference/internal/projection"
)

const source event.Source = "//scnehaux.com/organization-control"

func fixture(t *testing.T) (*projection.Projector, *db.Pool, context.Context) {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_INTEGRATION") != "" {
			t.Fatal("REQUIRE_INTEGRATION is set and TEST_DATABASE_URL is empty: the database this suite asserts against never came up")
		}
		t.Skip("TEST_DATABASE_URL is unset; set it to run the projection assertions against a real server")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	pool, err := db.Open(ctx, db.Config{Name: "projection-test", DSN: dsn, MaxConns: 4})
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)

	// A distinct consumer name per test AND per run, because inbox.Guard deduplicates per
	// (event_id, consumer).
	//
	// Per test, so one test's deliveries do not look like duplicates to the next. Per run, because
	// the golden envelope carries a fixed event identifier: with a name stable across runs, the
	// first run applied it and every run afterwards saw a duplicate and failed. The tests that mint
	// their own identifiers never noticed, which is why the suffix belongs here rather than in the
	// one test that tripped over it.
	projector, err := projection.New(pool, "test-"+t.Name()+"-"+newID(t).String())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return projector, pool, ctx
}

func newID(t *testing.T) id.UUID {
	t.Helper()
	minted, err := id.NewV7()
	if err != nil {
		t.Fatalf("minting an identifier: %v", err)
	}
	return minted
}

// subject is one (Tenant, Principal, Membership) triple, held together because enforcement asks
// about the pair while the event carries all three. Minting fresh tenant and principal
// identifiers per envelope would make two deliveries for the same membership describe two
// different contexts, and the monotonicity guard would then compare unrelated rows.
type subject struct {
	tenant     id.UUID
	principal  id.UUID
	membership id.UUID
}

func newSubject(t *testing.T) subject {
	t.Helper()
	return subject{tenant: newID(t), principal: newID(t), membership: newID(t)}
}

func revoked(t *testing.T, s subject, version int64) event.Envelope {
	t.Helper()
	return envelopeFor(t, s, version, projection.MembershipRevoked, "revoked")
}

func granted(t *testing.T, s subject, version int64) event.Envelope {
	t.Helper()
	return envelopeFor(t, s, version, projection.MembershipGranted, "active")
}

func envelopeFor(t *testing.T, s subject, version int64, typ event.Type, status string) event.Envelope {
	t.Helper()

	payload := projection.Payload{
		MembershipID: s.membership,
		TenantID:     s.tenant,
		PrincipalID:  s.principal,
		Version:      version,
		Status:       status,
	}
	envelope, err := event.New(source, typ, time.Now().UTC(), payload)
	if err != nil {
		t.Fatalf("building an envelope: %v", err)
	}
	// StreamPosition is what a published envelope carries; the dispatcher sets it from the
	// outbox sequence. Set here so the fixture matches what the consumer will really see.
	envelope.StreamPosition = version
	return envelope
}

func TestApplyingARevocationProjectsIt(t *testing.T) {
	projector, _, ctx := fixture(t)
	s := newSubject(t)

	outcome, err := projector.Apply(ctx, revoked(t, s, 3))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !outcome.Applied || outcome.Duplicate || outcome.Superseded {
		t.Fatalf("first delivery: applied = %v, duplicate = %v, superseded = %v",
			outcome.Applied, outcome.Duplicate, outcome.Superseded)
	}

	record, err := projector.Lookup(ctx, s.tenant, s.principal)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if record.Status != projection.Revoked || record.Version != 3 {
		t.Errorf("projected status = %v at version %d, want revoked at 3", record.Status, record.Version)
	}
}

// TestADuplicateDeliveryAppliesNothingTwice sends the identical envelope twice, the way a
// broker at-least-once delivery does.
func TestADuplicateDeliveryAppliesNothingTwice(t *testing.T) {
	projector, pool, ctx := fixture(t)
	s := newSubject(t)
	envelope := revoked(t, s, 4)

	first, err := projector.Apply(ctx, envelope)
	if err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	second, err := projector.Apply(ctx, envelope)
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}

	if !first.Applied {
		t.Error("the first delivery did not apply")
	}
	if !second.Duplicate {
		t.Error("the second delivery of the same event was not reported as a duplicate")
	}
	if second.Applied {
		t.Error("the second delivery applied an effect that was already applied")
	}

	// And exactly one row exists, which is the claim that matters to a caller.
	var rows int
	if err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM projection.membership WHERE membership_id = $1`,
			s.membership.String()).Scan(&rows)
	}); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if rows != 1 {
		t.Errorf("%d rows for one membership, want 1", rows)
	}
}

// TestOutOfOrderDeliveryIsHarmless is the assertion that frees the broker choice.
//
// Version 9 is applied, then version 5 arrives — the reordering a broker without per-key
// ordering will eventually produce. The older event must be accounted for and must not
// regress the state.
func TestOutOfOrderDeliveryIsHarmless(t *testing.T) {
	projector, _, ctx := fixture(t)
	s := newSubject(t)

	if _, err := projector.Apply(ctx, revoked(t, s, 9)); err != nil {
		t.Fatalf("applying version 9: %v", err)
	}

	late, err := projector.Apply(ctx, revoked(t, s, 5))
	if err != nil {
		t.Fatalf("applying version 5: %v", err)
	}
	if !late.Superseded {
		t.Errorf("the late delivery reported applied = %v, duplicate = %v, superseded = %v; want superseded",
			late.Applied, late.Duplicate, late.Superseded)
	}

	record, err := projector.Lookup(ctx, s.tenant, s.principal)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if record.Version != 9 {
		t.Errorf("version regressed to %d after an out-of-order delivery, want 9", record.Version)
	}
}

func TestANewerDeliveryAdvancesTheVersion(t *testing.T) {
	projector, _, ctx := fixture(t)
	s := newSubject(t)

	if _, err := projector.Apply(ctx, revoked(t, s, 2)); err != nil {
		t.Fatalf("applying version 2: %v", err)
	}
	advanced, err := projector.Apply(ctx, revoked(t, s, 11))
	if err != nil {
		t.Fatalf("applying version 11: %v", err)
	}
	if !advanced.Applied {
		t.Error("a newer version did not apply")
	}

	record, err := projector.Lookup(ctx, s.tenant, s.principal)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if record.Version != 11 {
		t.Errorf("version = %d after a newer delivery, want 11", record.Version)
	}
}

func TestAnUnknownEventTypeIsRefusedRatherThanIgnored(t *testing.T) {
	projector, _, ctx := fixture(t)

	envelope := revoked(t, newSubject(t), 1)
	// A type this consumer does not project: Tenant lifecycle belongs to a different consumer.
	envelope.Type = "com.scnehaux.organization.tenant.lifecycle.requested"

	// Refused, not silently skipped: a consumer that swallows an unrecognised type reports
	// success for work it never did, and the dispatcher marks the row published.
	if _, err := projector.Apply(ctx, envelope); err == nil {
		t.Fatal("Apply accepted an event type this consumer does not project")
	}
}

func TestAMalformedPayloadIsRefused(t *testing.T) {
	projector, _, ctx := fixture(t)

	envelope := revoked(t, newSubject(t), 1)
	envelope.Data = json.RawMessage(`{"membership_id":"11111111-1111-4111-8111-11111111111a","version":0}`)

	if _, err := projector.Apply(ctx, envelope); err == nil {
		t.Fatal("Apply accepted a payload with a non-positive version")
	}
}

// TestAgeRefusesUntilTheConsumerHasBootstrapped is the sound half of freshness on this side.
//
// Age answers "when did the last event land", which the principal review correctly refuses as a
// security invariant: one event delivered now makes it look fresh while an older one is still in
// flight. What it CAN answer soundly is whether this consumer has any positive authority at all, and
// a consumer with no snapshot has none.
func TestAgeRefusesUntilTheConsumerHasBootstrapped(t *testing.T) {
	projector, _, ctx := fixture(t)

	if _, err := projector.Apply(ctx, revoked(t, newSubject(t), 1)); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// Applied an event and still not bootstrapped: exactly the state the bootstrap contract exists
	// to make visible -- a model holding everything since it connected and nothing before.
	if _, err := projector.Age(ctx); !errors.Is(err, projection.ErrNotBootstrapped) {
		t.Fatalf("Age returned %v; want ErrNotBootstrapped before a snapshot", err)
	}

	seeded := newSubject(t)
	if err := projector.Seed(ctx, []projection.Seeded{{
		MembershipID: seeded.membership,
		TenantID:     seeded.tenant,
		PrincipalID:  seeded.principal,
		Status:       projection.Active,
		Version:      1,
	}}, 1000, true); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	age, err := projector.Age(ctx)
	if err != nil {
		t.Fatalf("Age after bootstrapping: %v", err)
	}
	if age < 0 || age > time.Minute {
		t.Errorf("age = %s immediately after seeding, want something under a minute", age)
	}

	position, err := projector.Position(ctx)
	if err != nil {
		t.Fatalf("Position: %v", err)
	}
	if position.SnapshotMark == nil || *position.SnapshotMark != 1000 {
		t.Errorf("snapshot mark = %v, want 1000", position.SnapshotMark)
	}
	if position.BootstrappedAt == nil {
		t.Error("bootstrapped_at was not recorded")
	}
}

// TestANewMembershipIsNotOlderThanTheRevokedOneItReplaces is the ordering rule the principal review
// required before the four event types landed.
//
// membership_version is monotonic per membership and says nothing across memberships. Membership A
// revoked at version 5, then membership B granted at version 1 for the same pair: comparing 1 against
// 5 would discard the grant and leave the revocation standing forever. The producer's stream position
// is what orders the two.
func TestANewMembershipIsNotOlderThanTheRevokedOneItReplaces(t *testing.T) {
	projector, _, ctx := fixture(t)
	first := newSubject(t)

	revocation := revoked(t, first, 5)
	revocation.StreamPosition = 500
	if _, err := projector.Apply(ctx, revocation); err != nil {
		t.Fatalf("revoking membership A at version 5: %v", err)
	}

	// A different membership for the same (Tenant, Principal), granted afterwards at version 1.
	replacement := first
	replacement.membership = newID(t)
	grant := granted(t, replacement, 1)
	grant.StreamPosition = 501

	outcome, err := projector.Apply(ctx, grant)
	if err != nil {
		t.Fatalf("granting membership B at version 1: %v", err)
	}
	if !outcome.Applied {
		t.Fatalf("the replacement grant was discarded: applied = %v, superseded = %v. "+
			"membership_version was compared across two different memberships",
			outcome.Applied, outcome.Superseded)
	}

	record, err := projector.Lookup(ctx, first.tenant, first.principal)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	switch {
	case record.Status != projection.Active:
		t.Errorf("status = %s after a replacement grant, want active", record.Status)
	case record.MembershipID != replacement.membership:
		t.Errorf("membership_id = %s, want the replacement %s", record.MembershipID, replacement.membership)
	case record.Version != 1:
		t.Errorf("version = %d, want the replacement's 1", record.Version)
	}
}

// TestAnOlderEventForADifferentMembershipIsSuperseded is the other direction, so the rule is not
// simply "a different membership always wins".
func TestAnOlderEventForADifferentMembershipIsSuperseded(t *testing.T) {
	projector, _, ctx := fixture(t)
	current := newSubject(t)

	grant := granted(t, current, 2)
	grant.StreamPosition = 900
	if _, err := projector.Apply(ctx, grant); err != nil {
		t.Fatalf("granting the current membership: %v", err)
	}

	stale := current
	stale.membership = newID(t)
	late := revoked(t, stale, 9)
	late.StreamPosition = 800 // committed before the grant above

	outcome, err := projector.Apply(ctx, late)
	if err != nil {
		t.Fatalf("applying the earlier event: %v", err)
	}
	if !outcome.Superseded {
		t.Errorf("an event committed earlier for a replaced membership was applied: %+v", outcome)
	}

	record, err := projector.Lookup(ctx, current.tenant, current.principal)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if record.Status != projection.Active {
		t.Errorf("status = %s; an earlier event for a different membership overwrote the current one", record.Status)
	}
}
