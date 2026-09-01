package projection_test

// The golden envelope: a real event, captured from organization-control's outbox, applied by this
// consumer unchanged.
//
// It exists because every other test in this package builds its payload from projection.Payload —
// the same struct the code under test decodes into. A fixture and a decoder that agree with each
// other prove only that they agree. The first end-to-end run refused every delivery:
//
//	400 projection: payload does not carry the members this consumer needs:
//	    membership_id and a positive version are required
//
// The producer's field is membership_version; this consumer called it version. Nothing in the suite
// could have caught that, because nothing in the suite had ever seen a producer.
//
// So this file is the conformance artifact the estate's review asked for, in its smallest useful
// form: bytes this consumer did not author. Replacing it means re-capturing from a real outbox row,
// not editing it to match the code.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/event"

	"github.com/anshacerbia2/foundation-reference/internal/projection"
)

func TestTheGoldenEnvelopeIsAppliedAsTheProducerSentIt(t *testing.T) {
	projector, pool, ctx := fixture(t)

	raw, err := os.ReadFile(filepath.Join("testdata", "membership-security-revoked.json"))
	if err != nil {
		t.Fatalf("reading the golden envelope: %v", err)
	}

	var envelope event.Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("the golden envelope no longer decodes as a CloudEvents envelope: %v", err)
	}

	// The type is asserted rather than trusted: if the producer renames its event, this fixture is
	// stale and the failure should say so here rather than as a silently unprojected delivery.
	if envelope.Type != projection.MembershipRevoked {
		t.Fatalf("the golden envelope carries %s, and this consumer projects %s",
			envelope.Type, projection.MembershipRevoked)
	}

	var payload projection.Payload
	if err := json.Unmarshal(envelope.Data, &payload); err != nil {
		t.Fatalf("decoding the golden payload: %v", err)
	}

	// The golden envelope names a real (Tenant, Principal) pair at a fixed version, so a database
	// that has already seen that pair at the same or a higher version supersedes it -- and the test
	// would report "not applied" for a consumer that is working correctly. Every other test here
	// mints its own identifiers and never meets this. Cleared rather than worked around, because
	// what this test asserts is decoding and projection, not what the row happened to hold before.
	if err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM projection.membership WHERE tenant_id = $1 AND principal_id = $2`,
			payload.TenantID.String(), payload.PrincipalID.String())
		return err
	}); err != nil {
		t.Fatalf("clearing the pair the golden envelope names: %v", err)
	}

	outcome, err := projector.Apply(ctx, envelope)
	if err != nil {
		t.Fatalf("applying a real event failed, which is the defect this fixture exists to catch: %v", err)
	}
	if !outcome.Applied {
		t.Fatalf("a real event was not applied: applied = %v, duplicate = %v, superseded = %v",
			outcome.Applied, outcome.Duplicate, outcome.Superseded)
	}

	// And the members enforcement depends on arrived intact. A payload that decoded without error
	// but yielded a zero tenant would leave every enforcement check reading the wrong row, and the
	// apply above would still have reported success.
	if payload.TenantID.IsNil() || payload.PrincipalID.IsNil() {
		t.Fatal("the golden payload decoded with a nil tenant or principal")
	}

	applied, err := projector.LookupMembership(ctx, payload.MembershipID)
	if err != nil {
		t.Fatalf("the event applied but the pair it names cannot be read back: %v", err)
	}
	switch {
	case applied.Status != projection.Revoked:
		t.Error("the membership is not revoked after applying a revocation")
	case applied.Version != payload.Version:
		t.Errorf("projected version %d, and the producer sent membership_version %d",
			applied.Version, payload.Version)
	case applied.Version == 0:
		t.Error("the projected version is zero, so the producer's version field was not read")
	}
}
