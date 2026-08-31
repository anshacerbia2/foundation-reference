// Package httpapi is this consumer's surface: one intake for deliveries, and one protected
// operation per security class so every fail behaviour can be exercised by hand.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/anshacerbia2/foundation-platform/event"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/observability"

	"github.com/anshacerbia2/reference-consumer/internal/projection"
)

const maxDeliveryBody = 1 << 20

// Operation binds a route to a security class at the point the route is declared.
//
// The class travels with the route rather than living in a document or a lookup table
// keyed by path, because a route added without a class would otherwise inherit whatever
// default exists — and any default is wrong for some route. TestEveryOperationDeclaresAClass
// is what makes that structural rather than aspirational.
type Operation struct {
	Method  string
	Pattern string
	Class   Class
}

// operations is the protected surface. Each class appears once so all four fail behaviours
// are reachable by hand; a real product would have many routes per class.
var operations = []Operation{
	{http.MethodGet, "/v1/directory/{membership_id}", LowRisk},
	{http.MethodGet, "/v1/payroll/{membership_id}", HighConfidentiality},
	{http.MethodPost, "/v1/administration/{membership_id}", Privileged},
	{http.MethodPost, "/v1/deletion/{membership_id}", Irreversible},
}

// Operations exposes the table for tests.
func Operations() []Operation {
	out := make([]Operation, len(operations))
	copy(out, operations)
	return out
}

// Deliveries is what the routes need from the projection: apply an event, and report how
// stale the answer is. An interface for the same reason the enforcer takes one -- the routes
// can then be tested without a database, and the test that matters most here is the one
// asserting a route cannot be mounted unauthenticated.
type Deliveries interface {
	Apply(ctx context.Context, envelope event.Envelope) (projection.Outcome, error)
	Age(ctx context.Context) (time.Duration, error)
}

type Config struct {
	Projector Deliveries
	Enforcer  *Enforcer
	Telemetry *observability.Telemetry

	// Delivery and Caller are the two authentication middlewares, kept separate because the
	// two authorities are different: a workload that may apply events, and a principal that
	// may ask whether it can act. One middleware over both would let any caller of an
	// operation forge a revocation, or forge its absence by replaying an older version.
	//
	// Both are required. A nil middleware here would mount the route unauthenticated, and an
	// unauthenticated intake is a projection anyone can write.
	Delivery func(http.Handler) http.Handler
	Caller   func(http.Handler) http.Handler
}

// Surface separates the probes from everything else, the way organization-control does.
// One mux with an exemption list is edited by whoever adds a route, and the failure mode of
// forgetting is an unauthenticated route; identity-control learned the other half of it in
// an outage where the middleware also wrapped /readyz and no replica entered service.
type Surface struct {
	Probes *http.ServeMux
	API    *http.ServeMux
}

func Routes(cfg Config) (*Surface, error) {
	if cfg.Projector == nil {
		return nil, errors.New("httpapi: a projector is required")
	}
	if cfg.Enforcer == nil {
		return nil, errors.New("httpapi: an enforcer is required")
	}
	// Refused at construction rather than defaulted to a pass-through. A missing middleware
	// is the one configuration mistake that produces no symptom: everything works, and
	// nothing is authenticated.
	if cfg.Delivery == nil {
		return nil, errors.New("httpapi: delivery authentication is required; an unauthenticated intake is a projection anyone can write")
	}
	if cfg.Caller == nil {
		return nil, errors.New("httpapi: caller authentication is required")
	}

	probes := http.NewServeMux()
	probes.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	probes.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		// Readiness reports the projection's age without judging it. Whether an age is
		// acceptable is a per-class question, and a probe that answered it for the whole
		// process would take a replica out of service for traffic it could still serve.
		age, err := cfg.Projector.Age(r.Context())
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "projection": "cold"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":            "ok",
			"projection_age_ms": age.Milliseconds(),
		})
	})

	api := http.NewServeMux()

	// The intake. A broker adapter posts an envelope here; the transport is deliberately
	// boring so the properties under test are the consumer's, not the transport's.
	api.Handle("POST /v1/deliveries", cfg.Delivery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDeliveryBody))
		decoder.DisallowUnknownFields()

		var envelope event.Envelope
		if err := decoder.Decode(&envelope); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("the delivery is not a CloudEvents envelope: %v", err),
			})
			return
		}

		outcome, err := cfg.Projector.Apply(r.Context(), envelope)
		switch {
		case errors.Is(err, projection.ErrUnknownType):
			// Poison rather than a retryable failure: redelivering an event this consumer
			// does not apply will fail identically forever. 400 tells the dispatcher that.
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		case errors.Is(err, projection.ErrMalformed):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		case err != nil:
			// Anything else is worth retrying, and 503 is what says so.
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusAccepted, map[string]any{
			"applied":    outcome.Applied,
			"duplicate":  outcome.Duplicate,
			"superseded": outcome.Superseded,
			"version":    outcome.Record.Version,
		})
	})))

	for _, operation := range operations {
		if _, err := PolicyFor(operation.Class); err != nil {
			return nil, fmt.Errorf("httpapi: route %s %s: %w", operation.Method, operation.Pattern, err)
		}
		// The role is chosen here, beside the security class, so both properties of a route
		// are stated in one place and neither can be inherited from a default.
		api.Handle(operation.Method+" "+operation.Pattern, cfg.Caller(protected(cfg.Enforcer, operation)))
	}

	return &Surface{Probes: probes, API: api}, nil
}

func protected(enforcer *Enforcer, operation Operation) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		membershipID, err := id.Parse(r.PathValue("membership_id"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "membership_id is not a UUID"})
			return
		}

		decision, err := enforcer.Decide(r.Context(), operation.Class, membershipID)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"operation": operation.Pattern,
				"class":     operation.Class,
				"allowed":   false,
				"reason":    decision.Reason,
			})
			return
		}

		body := map[string]any{
			"operation": operation.Pattern,
			"class":     operation.Class,
			"allowed":   decision.Allow,
			"reason":    decision.Reason,
			"stale":     decision.Stale,
			"age_ms":    decision.Age.Milliseconds(),
		}

		if !decision.Allow {
			// 403 rather than 401: the caller is who they say they are, and their
			// membership no longer confers the authority this operation needs.
			writeJSON(w, http.StatusForbidden, body)
			return
		}
		writeJSON(w, http.StatusOK, body)
	}
}

// Mount composes the two muxes. Probes are never wrapped by the API chain.
func (s *Surface) Mount(probeChain, apiChain func(http.Handler) http.Handler) http.Handler {
	root := http.NewServeMux()
	root.Handle("/healthz", probeChain(s.Probes))
	root.Handle("/readyz", probeChain(s.Probes))
	root.Handle("/", apiChain(s.API))
	return root
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
