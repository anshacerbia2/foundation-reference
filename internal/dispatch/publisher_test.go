package dispatch_test

// The status mapping is the whole contract between this adapter and the dispatcher, and getting it
// wrong is silent in both directions: retrying poison spends the attempt budget of every event
// behind it, and dead-lettering a retryable failure turns a credential rotation into data loss.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/event"
	"github.com/anshacerbia2/foundation-platform/observability"
	"github.com/anshacerbia2/foundation-platform/outbox"

	"github.com/anshacerbia2/foundation-reference/internal/dispatch"
)

func testTelemetry(t *testing.T) *observability.Telemetry {
	t.Helper()
	telemetry, err := observability.New(observability.Config{
		Deployable: "organization-dispatcher",
		System:     "SAD-004",
		Logger:     slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)),
	})
	if err != nil {
		t.Fatalf("telemetry: %v", err)
	}
	return telemetry
}

func envelope(t *testing.T) event.Envelope {
	t.Helper()
	built, err := event.New(
		"//scnehaux.com/organization-control",
		"com.scnehaux.organization.membership.security.revoked",
		time.Now().UTC(),
		map[string]any{"membership_id": "01a05800-0000-7000-8000-000000000001", "version": 3})
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	built.StreamPosition = 3
	return built
}

func publisherFor(t *testing.T, handler http.HandlerFunc) *dispatch.HTTPPublisher {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	publisher, err := dispatch.NewHTTPPublisher(server.URL+"/v1/deliveries", "test-token",
		2*time.Second, testTelemetry(t))
	if err != nil {
		t.Fatalf("NewHTTPPublisher: %v", err)
	}
	return publisher
}

func TestAnAcceptedDeliveryIsPublished(t *testing.T) {
	publisher := publisherFor(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q, want the delivery credential", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q", got)
		}
		w.WriteHeader(http.StatusAccepted)
	})

	if err := publisher.Publish(context.Background(), envelope(t)); err != nil {
		t.Errorf("Publish: %v", err)
	}
}

// TestTheConsumersPermanentRefusalsArePoison covers the statuses a retry cannot fix. Retrying them
// delays the dead letter and spends the attempt budget of every event queued behind.
func TestTheConsumersPermanentRefusalsArePoison(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusConflict, http.StatusUnprocessableEntity} {
		publisher := publisherFor(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"this consumer does not project that type"}`))
		})

		err := publisher.Publish(context.Background(), envelope(t))
		if !errors.Is(err, outbox.ErrPoison) {
			t.Errorf("status %d produced %v, want ErrPoison", status, err)
		}
	}
}

// TestACredentialFailureIsRetryableRatherThanPoison is the mapping worth arguing about.
//
// 401 and 403 look permanent from inside one request and are not: a withdrawn or expired
// credential is an operator's problem, and dead-lettering the estate's events over it would make a
// credential rotation lose data.
func TestACredentialFailureIsRetryableRatherThanPoison(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		publisher := publisherFor(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		})

		err := publisher.Publish(context.Background(), envelope(t))
		switch {
		case err == nil:
			t.Errorf("status %d was reported as published", status)
		case errors.Is(err, outbox.ErrPoison):
			t.Errorf("status %d was classified poison; a credential failure must retry", status)
		}
	}
}

func TestAConsumerOutageIsRetryable(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusInternalServerError, http.StatusTooManyRequests} {
		publisher := publisherFor(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		})

		err := publisher.Publish(context.Background(), envelope(t))
		switch {
		case err == nil:
			t.Errorf("status %d was reported as published", status)
		case errors.Is(err, outbox.ErrPoison):
			t.Errorf("status %d was classified poison", status)
		}
	}
}

// TestATimeoutIsRetryable is the ambiguous delivery: the consumer may have committed and the
// acknowledgement been lost. Retrying is the only available choice, and it is safe only because the
// consumer deduplicates inside the transaction that applies the effect.
func TestATimeoutIsRetryable(t *testing.T) {
	blocked := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-blocked
		w.WriteHeader(http.StatusAccepted)
	}))

	// Cleanup order matters and is LIFO, so the handler is released before the server is closed.
	// Registered the other way round, server.Close waits for the in-flight handler that is still
	// blocked on this channel, and the test hangs rather than failing.
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(blocked) })

	publisher, err := dispatch.NewHTTPPublisher(server.URL+"/v1/deliveries", "test-token",
		50*time.Millisecond, testTelemetry(t))
	if err != nil {
		t.Fatalf("NewHTTPPublisher: %v", err)
	}

	publishErr := publisher.Publish(context.Background(), envelope(t))
	switch {
	case publishErr == nil:
		t.Error("a timed-out delivery was reported as published")
	case errors.Is(publishErr, outbox.ErrPoison):
		t.Error("a timeout was classified poison; the consumer may have committed")
	}
}

func TestTheCorrelationIdentifierTravelsWithTheDelivery(t *testing.T) {
	seen := make(chan string, 1)
	publisher := publisherFor(t, func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("X-Correlation-Id")
		w.WriteHeader(http.StatusAccepted)
	})

	correlation, err := event.New("//scnehaux.com/test", "com.scnehaux.organization.membership.security.revoked", time.Now(), map[string]any{})
	if err != nil {
		t.Fatalf("minting an identifier: %v", err)
	}
	ctx := observability.WithCorrelationID(context.Background(), correlation.ID)

	if err := publisher.Publish(ctx, envelope(t)); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got := <-seen; got != correlation.ID.String() {
		t.Errorf("X-Correlation-Id = %q, want %s", got, correlation.ID)
	}
}

func TestConstructionRefusesAnUnauthenticatedPublisher(t *testing.T) {
	if _, err := dispatch.NewHTTPPublisher("http://127.0.0.1:8096/v1/deliveries", "", time.Second, testTelemetry(t)); err == nil {
		t.Error("NewHTTPPublisher accepted an empty credential; an anonymous intake is a projection anyone can write")
	}
	if _, err := dispatch.NewHTTPPublisher("not-a-url", "token", time.Second, testTelemetry(t)); err == nil {
		t.Error("NewHTTPPublisher accepted a relative endpoint")
	}
}
