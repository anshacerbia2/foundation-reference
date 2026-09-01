// Package dispatch publishes outbox rows to a consumer over HTTP.
//
// It satisfies `outbox.Publisher`, which is a one-method interface declared by the substrate on the
// consuming side. Which transport carries an event is therefore one adapter, and this is it: a
// broker replaces this file and nothing else.
//
// HTTP first, deliberately. TDD-organization-control-003 leaves the broker open, and choosing one
// is an operational decision the estate has not made. What Proof A needs is a transport whose
// anomalies can be produced on demand — duplicate, reorder, timeout, outage — and a deterministic
// adapter does that better than a real broker, which has to be provoked.
//
// # Why this lives here and not in organization-control
//
// It was written there first, and archcheck refused it: ADR-ORG-001 §5.4 gives that service no
// outbound HTTP route, and its arch.json says in as many words that widening the exception list
// "would retire the rule while leaving it written down". The rule is right and the placement was
// wrong. organization-control keeps what it owns -- the outbox, and the narrow database role a
// delivery worker runs as -- and the transport that reaches another service over HTTP lives in the
// proof article instead.
//
// The consequence is worth stating rather than hiding: until a broker is chosen, the deployable
// that drains the outbox is part of this repository. Once the transport is a broker client rather
// than an HTTP call, it can move into organization-control without touching that prohibition.
package dispatch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/event"
	"github.com/anshacerbia2/foundation-platform/observability"
	"github.com/anshacerbia2/foundation-platform/outbox"
)

// maxDetail bounds what a consumer's refusal contributes to a dead-letter row. A consumer
// returning a large body should not be able to fill this database through its error path.
const maxDetail = 4 << 10

// HTTPPublisher posts CloudEvents envelopes to one consumer.
type HTTPPublisher struct {
	endpoint  string
	token     string
	client    *http.Client
	telemetry *observability.Telemetry
}

func NewHTTPPublisher(endpoint, token string, timeout time.Duration, telemetry *observability.Telemetry) (*HTTPPublisher, error) {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return nil, errors.New("dispatch: the consumer endpoint is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("dispatch: %q is not an absolute URL", endpoint)
	}
	if strings.TrimSpace(token) == "" {
		// Refused rather than sent unauthenticated. An intake that accepts anonymous deliveries is
		// a projection anyone can write, and a dispatcher that discovered this per request would
		// dead-letter every event before anyone noticed the credential was missing.
		return nil, errors.New("dispatch: a delivery credential is required")
	}
	if timeout <= 0 {
		return nil, errors.New("dispatch: the publication timeout must be positive")
	}
	if telemetry == nil {
		return nil, errors.New("dispatch: telemetry is required")
	}

	return &HTTPPublisher{
		endpoint:  trimmed,
		token:     token,
		client:    &http.Client{Timeout: timeout},
		telemetry: telemetry,
	}, nil
}

// Publish delivers one envelope.
//
// The status mapping is the whole contract with the dispatcher, and it decides whether a failure
// retries or dead-letters:
//
//   - 2xx: published.
//   - 400, 409, 422: poison. The consumer will refuse this event identically forever — an
//     unregistered type, a payload it cannot read — so retrying only delays the dead letter and
//     spends the attempt budget of every event behind it.
//   - anything else, including a transport failure and a timeout: retryable. That deliberately
//     includes 401 and 403: a withdrawn or expired credential is an operator's problem to fix, and
//     dead-lettering the estate's events because of it would turn a credential rotation into data
//     loss.
//
// A timeout is retryable and is also the ambiguous case: the consumer may have committed and the
// acknowledgement been lost. That is safe only because the consumer deduplicates inside the
// transaction that applies the effect, which foundation-reference asserts.
func (p *HTTPPublisher) Publish(ctx context.Context, envelope event.Envelope) error {
	body, err := json.Marshal(envelope)
	if err != nil {
		// The envelope came out of this system's own outbox and failed to marshal, so no retry
		// will fix it. Poison rather than an endless loop over a row nobody can send.
		return fmt.Errorf("%w: encoding %s: %v", outbox.ErrPoison, envelope.ID, err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("dispatch: building the delivery for %s: %w", envelope.ID, err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+p.token)

	// The correlation identifier travels with the delivery, so the producer's log line, this
	// publication, and the consumer's refusal all join on one value. Without it the end-to-end
	// delay is two stopwatches nobody can reconcile.
	if correlation, ok := observability.CorrelationID(ctx); ok {
		request.Header.Set("X-Correlation-Id", correlation.String())
	}

	response, err := p.client.Do(request)
	if err != nil {
		// Includes the timeout, and therefore includes the case where the consumer committed and
		// the response was lost. Retryable on purpose.
		return fmt.Errorf("dispatch: delivering %s: %w", envelope.ID, err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode >= 200 && response.StatusCode < 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxDetail))
		return nil
	}

	detail, _ := io.ReadAll(io.LimitReader(response.Body, maxDetail))
	trimmed := strings.TrimSpace(string(detail))

	switch response.StatusCode {
	case http.StatusBadRequest, http.StatusConflict, http.StatusUnprocessableEntity:
		return fmt.Errorf("%w: the consumer refused %s with %d: %s",
			outbox.ErrPoison, envelope.ID, response.StatusCode, trimmed)
	default:
		return fmt.Errorf("dispatch: the consumer answered %d for %s: %s",
			response.StatusCode, envelope.ID, trimmed)
	}
}
