package projection_test

// The failure the principal review named as the most important one in Proof A, and the one that
// separates "we retry when the consumer is down" from "at-least-once delivery with an idempotent
// consumer":
//
//	dispatcher -> POST event -> consumer applies it and COMMITS
//	                         -> the HTTP response is lost
//	dispatcher concludes the delivery failed -> retries the same event
//
// The consumer already committed. From the dispatcher's side the two cases are
// indistinguishable, so the retry is not optional and cannot be prevented — which makes the
// consumer's behaviour on redelivery the whole safety property.
//
// Two things must hold, and only the first is obvious:
//
//   - the effect must not be applied twice
//   - the retry must be ACKNOWLEDGED as success, not answered with an error
//
// The second is what stops the loop. A consumer that answers "conflict" or "already processed"
// with a 4xx or 5xx leaves the dispatcher retrying an event that is already applied, until the
// attempt limit dead-letters a delivery that in fact succeeded — and an operator then
// investigating a dead letter finds the effect present and the record saying it failed.

import (
	"testing"

	"github.com/anshacerbia2/foundation-reference/internal/projection"
)

func TestAnAcknowledgementLostAfterCommitIsSafeToRetry(t *testing.T) {
	projector, _, ctx := fixture(t)
	s := newSubject(t)
	envelope := revoked(t, s, 6)

	// The delivery that succeeded. Its acknowledgement never reached the dispatcher.
	committed, err := projector.Apply(ctx, envelope)
	if err != nil {
		t.Fatalf("the first delivery failed, which is not the case under test: %v", err)
	}
	if !committed.Applied {
		t.Fatal("the first delivery did not apply, so the ambiguity being tested never arose")
	}

	before, err := projector.LookupMembership(ctx, s.membership)
	if err != nil {
		t.Fatalf("reading the state the first delivery produced: %v", err)
	}

	// The dispatcher, having seen no acknowledgement, retries the identical envelope.
	retried, err := projector.Apply(ctx, envelope)

	// Not an error. This is the assertion that stops the retry loop: the consumer reports a
	// complete, successful outcome for a delivery it had already applied.
	if err != nil {
		t.Fatalf("the retry after a lost acknowledgement returned an error, which would keep the "+
			"dispatcher retrying an applied event until it dead-lettered a delivery that succeeded: %v", err)
	}
	if !retried.Duplicate {
		t.Errorf("the retry reported applied = %v, duplicate = %v, superseded = %v; want duplicate",
			retried.Applied, retried.Duplicate, retried.Superseded)
	}
	if retried.Applied {
		t.Error("the retry applied the effect a second time")
	}

	after, err := projector.LookupMembership(ctx, s.membership)
	if err != nil {
		t.Fatalf("reading the state after the retry: %v", err)
	}

	// No regression and no advance: the state after the retry is the state the first delivery
	// produced, to the version and the instant it was applied.
	if after.Version != before.Version {
		t.Errorf("version moved from %d to %d across a retry of the same event", before.Version, after.Version)
	}
	if !after.AppliedAt.Equal(before.AppliedAt) {
		t.Errorf("applied_at moved from %s to %s across a retry, so the row was rewritten",
			before.AppliedAt, after.AppliedAt)
	}
	if after.Status != projection.Revoked {
		t.Error("the membership is no longer revoked after a retry of its revocation")
	}
}

// TestARetryAfterCommitIsSafeEvenWhenAnotherEventLanded covers the ordering that makes the
// simple version of the test misleading.
//
// Between the lost acknowledgement and the retry, a newer revocation arrives and is applied. The
// retry of the older delivery must still be acknowledged, and must not drag the state back — the
// deduplication guard answers first, and the monotonicity guard stands behind it.
func TestARetryAfterCommitIsSafeEvenWhenAnotherEventLanded(t *testing.T) {
	projector, _, ctx := fixture(t)
	s := newSubject(t)

	older := revoked(t, s, 3)
	if _, err := projector.Apply(ctx, older); err != nil {
		t.Fatalf("applying version 3: %v", err)
	}
	if _, err := projector.Apply(ctx, revoked(t, s, 8)); err != nil {
		t.Fatalf("applying version 8: %v", err)
	}

	retried, err := projector.Apply(ctx, older)
	if err != nil {
		t.Fatalf("the retry of the older delivery returned an error: %v", err)
	}
	if !retried.Duplicate {
		t.Errorf("the retry reported duplicate = %v; want true", retried.Duplicate)
	}

	record, err := projector.LookupMembership(ctx, s.membership)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if record.Version != 8 {
		t.Errorf("version = %d after retrying an older delivery, want 8", record.Version)
	}
}
