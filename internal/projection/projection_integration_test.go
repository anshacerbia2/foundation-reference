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
	"os"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/event"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/reference-consumer/internal/projection"
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

	// A distinct consumer name per test, because inbox.Guard deduplicates per
	// (event_id, consumer): a shared name would let one test's deliveries look like
	// duplicates to the next.
	projector, err := projection.New(pool, "test-"+t.Name())
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

func revoked(t *testing.T, membershipID id.UUID, version int64) event.Envelope {
	t.Helper()

	payload := projection.Payload{
		MembershipID: membershipID,
		TenantID:     newID(t),
		PrincipalID:  newID(t),
		Version:      version,
	}
	envelope, err := event.New(source, projection.MembershipRevoked, time.Now().UTC(), payload)
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
	membershipID := newID(t)

	outcome, err := projector.Apply(ctx, revoked(t, membershipID, 3))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !outcome.Applied || outcome.Duplicate || outcome.Superseded {
		t.Fatalf("first delivery: applied = %v, duplicate = %v, superseded = %v",
			outcome.Applied, outcome.Duplicate, outcome.Superseded)
	}

	record, err := projector.Lookup(ctx, membershipID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !record.Revoked || record.Version != 3 {
		t.Errorf("projected revoked = %v at version %d, want true at 3", record.Revoked, record.Version)
	}
}

// TestADuplicateDeliveryAppliesNothingTwice sends the identical envelope twice, the way a
// broker at-least-once delivery does.
func TestADuplicateDeliveryAppliesNothingTwice(t *testing.T) {
	projector, pool, ctx := fixture(t)
	membershipID := newID(t)
	envelope := revoked(t, membershipID, 4)

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
			membershipID.String()).Scan(&rows)
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
	membershipID := newID(t)

	if _, err := projector.Apply(ctx, revoked(t, membershipID, 9)); err != nil {
		t.Fatalf("applying version 9: %v", err)
	}

	late, err := projector.Apply(ctx, revoked(t, membershipID, 5))
	if err != nil {
		t.Fatalf("applying version 5: %v", err)
	}
	if !late.Superseded {
		t.Errorf("the late delivery reported applied = %v, duplicate = %v, superseded = %v; want superseded",
			late.Applied, late.Duplicate, late.Superseded)
	}

	record, err := projector.Lookup(ctx, membershipID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if record.Version != 9 {
		t.Errorf("version regressed to %d after an out-of-order delivery, want 9", record.Version)
	}
}

func TestANewerDeliveryAdvancesTheVersion(t *testing.T) {
	projector, _, ctx := fixture(t)
	membershipID := newID(t)

	if _, err := projector.Apply(ctx, revoked(t, membershipID, 2)); err != nil {
		t.Fatalf("applying version 2: %v", err)
	}
	advanced, err := projector.Apply(ctx, revoked(t, membershipID, 11))
	if err != nil {
		t.Fatalf("applying version 11: %v", err)
	}
	if !advanced.Applied {
		t.Error("a newer version did not apply")
	}

	record, err := projector.Lookup(ctx, membershipID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if record.Version != 11 {
		t.Errorf("version = %d after a newer delivery, want 11", record.Version)
	}
}

func TestAnUnknownEventTypeIsRefusedRatherThanIgnored(t *testing.T) {
	projector, _, ctx := fixture(t)

	envelope := revoked(t, newID(t), 1)
	envelope.Type = "com.scnehaux.organization.membership.granted"

	// Refused, not silently skipped: a consumer that swallows an unrecognised type reports
	// success for work it never did, and the dispatcher marks the row published.
	if _, err := projector.Apply(ctx, envelope); err == nil {
		t.Fatal("Apply accepted an event type this consumer does not project")
	}
}

func TestAMalformedPayloadIsRefused(t *testing.T) {
	projector, _, ctx := fixture(t)

	envelope := revoked(t, newID(t), 1)
	envelope.Data = json.RawMessage(`{"membership_id":"11111111-1111-4111-8111-11111111111a","version":0}`)

	if _, err := projector.Apply(ctx, envelope); err == nil {
		t.Fatal("Apply accepted a payload with a non-positive version")
	}
}

// TestAgeReportsHowStaleTheAnswerIs is the input to every fail-open decision, so it is
// asserted rather than trusted.
func TestAgeReportsHowStaleTheAnswerIs(t *testing.T) {
	projector, _, ctx := fixture(t)

	if _, err := projector.Apply(ctx, revoked(t, newID(t), 1)); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	age, err := projector.Age(ctx)
	if err != nil {
		t.Fatalf("Age: %v", err)
	}
	if age < 0 || age > time.Minute {
		t.Errorf("age = %s immediately after applying, want something under a minute", age)
	}
}
