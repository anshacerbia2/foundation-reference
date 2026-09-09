package dispatch_test

// What a 2xx establishes.
//
// The dead-letter resolution contract accepts applied evidence as proof that this consumer
// holds an event, and applied evidence exists only when the consumer said so in
// outbox.ApplicationReceiptHeader. This adapter cannot claim it on the consumer's behalf --
// outbox.Receipt's field is unexported -- and these tests hold that the mapping from the
// consumer's answer to the evidence class is the one the contract expects.
//
// The case worth naming is the broker one. When this file is replaced by a broker client, the
// acknowledgement carries no such header, receipts become transport evidence, and resolution
// stops finding proof. That is the intended outcome, not a regression, and
// TestASuccessWithoutTheMarkerIsNotAppliedEvidence is the test that says so.

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/anshacerbia2/foundation-platform/outbox"
)

func TestTheConsumersMarkerBecomesAppliedEvidence(t *testing.T) {
	publisher := publisherFor(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(outbox.ApplicationReceiptHeader, outbox.ApplicationReceiptApplied)
		w.WriteHeader(http.StatusAccepted)
	})

	receipt, err := publisher.Publish(context.Background(), envelope(t))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got := receipt.Evidence(); got != outbox.EvidenceConsumerApplied {
		t.Errorf("evidence = %q, want %q", got, outbox.EvidenceConsumerApplied)
	}
}

// A 2xx alone establishes that something accepted the delivery. It does not establish that the
// consumer applied it: an older consumer, or a proxy answering on its behalf, produces exactly
// this. Recording it as applied evidence would let a resolution close an incident on the
// strength of a status code.
func TestASuccessWithoutTheMarkerIsNotAppliedEvidence(t *testing.T) {
	publisher := publisherFor(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})

	receipt, err := publisher.Publish(context.Background(), envelope(t))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got := receipt.Evidence(); got != outbox.EvidenceTransportAccepted {
		t.Errorf("evidence = %q, want %q -- a bare 2xx was recorded as though the consumer "+
			"had applied the event", got, outbox.EvidenceTransportAccepted)
	}
}

// A marker the two sides no longer agree on establishes nothing. The safe reading of "I do not
// recognise this" is the weak class, not the strong one.
func TestAnUnrecognisedMarkerIsNotAppliedEvidence(t *testing.T) {
	for _, marker := range []string{"APPLIED", "true", "yes", "applied-later"} {
		publisher := publisherFor(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(outbox.ApplicationReceiptHeader, marker)
			w.WriteHeader(http.StatusAccepted)
		})

		receipt, err := publisher.Publish(context.Background(), envelope(t))
		if err != nil {
			t.Fatalf("Publish with marker %q: %v", marker, err)
		}
		if got := receipt.Evidence(); got != outbox.EvidenceTransportAccepted {
			t.Errorf("marker %q produced %q, want %q", marker, got, outbox.EvidenceTransportAccepted)
		}
	}
}

// A refused delivery must carry no evidence at all, whatever headers came back with it. A
// consumer that sets the header on a path that did not apply the event -- or a proxy that sets
// it indiscriminately -- must not be able to produce resolution evidence for a failure.
func TestARefusalCarriesNoEvidenceEvenWithTheMarkerSet(t *testing.T) {
	for _, status := range []int{
		http.StatusBadRequest,
		http.StatusConflict,
		http.StatusServiceUnavailable,
		http.StatusUnauthorized,
	} {
		publisher := publisherFor(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(outbox.ApplicationReceiptHeader, outbox.ApplicationReceiptApplied)
			w.WriteHeader(status)
		})

		receipt, err := publisher.Publish(context.Background(), envelope(t))
		if err == nil {
			t.Errorf("status %d was reported as published", status)
			continue
		}
		if got := receipt.Evidence(); got == outbox.EvidenceConsumerApplied {
			t.Errorf("status %d returned applied evidence alongside an error; a refused "+
				"delivery must establish nothing", status)
		}
	}
}

// A timeout is the ambiguous case: the consumer may have applied the event and the response
// been lost. It is retryable, and it must establish nothing -- the producer did not witness an
// acknowledgement, so there is nothing to witness.
func TestATimeoutEstablishesNothing(t *testing.T) {
	publisher := publisherFor(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(outbox.ApplicationReceiptHeader, outbox.ApplicationReceiptApplied)
		// Never answer within the publisher's timeout.
		<-t.Context().Done()
	})

	receipt, err := publisher.Publish(context.Background(), envelope(t))
	if err == nil {
		t.Fatal("a timed-out delivery was reported as published")
	}
	if errors.Is(err, outbox.ErrPoison) {
		t.Error("a timeout was classified poison; the consumer may have committed")
	}
	if got := receipt.Evidence(); got == outbox.EvidenceConsumerApplied {
		t.Error("a timeout produced applied evidence")
	}
}
