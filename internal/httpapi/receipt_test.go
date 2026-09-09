package httpapi_test

// The application receipt this consumer emits.
//
// The producer records applied evidence for a delivery when this header comes back, and the
// dead-letter resolution contract accepts that class as proof this consumer holds the event.
// So the header is an assertion, and it has to be true on every path that sets it.
//
// What these tests hold is the shape of that: set once Apply has returned without error, and
// on no other path. A consumer that set it before applying, or on a refusal, would let a
// resolution close an incident whose event was never projected.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/event"
	"github.com/anshacerbia2/foundation-platform/outbox"

	"github.com/anshacerbia2/foundation-reference/internal/httpapi"
	"github.com/anshacerbia2/foundation-reference/internal/projection"
)

// applyFunc is a projector whose Apply behaviour each test chooses.
type applyFunc func(context.Context, event.Envelope) (projection.Outcome, error)

func (f applyFunc) Apply(ctx context.Context, e event.Envelope) (projection.Outcome, error) {
	return f(ctx, e)
}

func (applyFunc) Age(context.Context) (time.Duration, error) { return time.Second, nil }

func deliver(t *testing.T, apply applyFunc) *httptest.ResponseRecorder {
	t.Helper()

	surface, err := httpapi.Routes(httpapi.Config{
		Projector: apply,
		Enforcer:  enforcer(t, stubProjection{age: time.Second}, nil),
		Delivery:  passthrough,
		Caller:    passthrough,
	})
	if err != nil {
		t.Fatalf("Routes: %v", err)
	}

	envelope, err := event.New("//scnehaux.com/organization-control",
		"com.scnehaux.organization.membership.security.revoked", time.Now(),
		map[string]any{
			"membership_id":      "11111111-1111-4111-8111-111111111111",
			"tenant_id":          "22222222-2222-4222-8222-222222222222",
			"principal_id":       "33333333-3333-4333-8333-333333333333",
			"membership_version": 2,
		})
	if err != nil {
		t.Fatalf("minting an envelope: %v", err)
	}

	body, err := json.Marshal(envelope.WithStreamPosition(7))
	if err != nil {
		t.Fatalf("encoding the envelope: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/deliveries", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	surface.API.ServeHTTP(recorder, request)
	return recorder
}

func TestAnAppliedDeliveryCarriesTheApplicationReceipt(t *testing.T) {
	recorder := deliver(t, func(context.Context, event.Envelope) (projection.Outcome, error) {
		return projection.Outcome{Applied: true}, nil
	})

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get(outbox.ApplicationReceiptHeader); got != outbox.ApplicationReceiptApplied {
		t.Errorf("%s = %q, want %q -- without it the producer records only transport evidence "+
			"and no dead letter for this event can ever be resolved as replayed",
			outbox.ApplicationReceiptHeader, got, outbox.ApplicationReceiptApplied)
	}
}

// A duplicate carries it too, and that is correct rather than lenient: a duplicate means the
// inbox guard found this event already applied, so "this consumer has applied it" is true.
//
// This is the case the resolution path actually depends on. Replaying an abandoned delivery to
// a consumer that already has it produces exactly this, and refusing the receipt here would
// make the one operation the contract prescribes unable to produce its own evidence.
func TestADuplicateDeliveryCarriesTheApplicationReceipt(t *testing.T) {
	recorder := deliver(t, func(context.Context, event.Envelope) (projection.Outcome, error) {
		return projection.Outcome{Duplicate: true}, nil
	})

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get(outbox.ApplicationReceiptHeader); got != outbox.ApplicationReceiptApplied {
		t.Errorf("a duplicate did not carry the receipt (%q); a replay of an abandoned delivery "+
			"would then be unable to produce the evidence that resolves it", got)
	}
}

// Every refusal path. None of them applied anything, so none of them may assert that they did.
func TestARefusedDeliveryCarriesNoApplicationReceipt(t *testing.T) {
	cases := map[string]struct {
		outcome projection.Outcome
		err     error
		status  int
	}{
		"unknown type": {err: projection.ErrUnknownType, status: http.StatusBadRequest},
		"malformed":    {err: projection.ErrMalformed, status: http.StatusBadRequest},
		"unavailable":  {err: context.DeadlineExceeded, status: http.StatusServiceUnavailable},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			recorder := deliver(t, func(context.Context, event.Envelope) (projection.Outcome, error) {
				return c.outcome, c.err
			})

			if recorder.Code != c.status {
				t.Errorf("status = %d, want %d: %s", recorder.Code, c.status, recorder.Body.String())
			}
			if got := recorder.Header().Get(outbox.ApplicationReceiptHeader); got != "" {
				t.Errorf("a refused delivery asserted %s = %q; the producer would record "+
					"applied evidence for an event this consumer never projected",
					outbox.ApplicationReceiptHeader, got)
			}
		})
	}
}

// An undecodable body never reaches Apply, so it must never reach the header either.
func TestAnUndecodableDeliveryCarriesNoApplicationReceipt(t *testing.T) {
	surface, err := httpapi.Routes(httpapi.Config{
		Projector: stubDeliveries{},
		Enforcer:  enforcer(t, stubProjection{age: time.Second}, nil),
		Delivery:  passthrough,
		Caller:    passthrough,
	})
	if err != nil {
		t.Fatalf("Routes: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/deliveries",
		bytes.NewReader([]byte(`{"not":"an envelope"}`)))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	surface.API.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	if got := recorder.Header().Get(outbox.ApplicationReceiptHeader); got != "" {
		t.Errorf("an undecodable delivery asserted %s = %q", outbox.ApplicationReceiptHeader, got)
	}
}
