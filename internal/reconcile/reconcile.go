// Package reconcile runs this consumer's reconciliation with organization-control on the interval its
// registration declares.
//
// The owner decided on 2026-10-20 that the consumer reconciles itself (ADR-ORG-001 §5.7, amended): the
// party that holds the copy runs the comparison. Kubernetes states the same split for a controller:
// "Controllers that interact with external state find their desired state from the API server, then
// communicate directly with an external system to bring the current state closer in line."
// organization-control holds the declared interval and the record of every run
// (TDD-organization-control-002 §Reconciliation Interval), so this package reads both from the
// consumer's own registration rather than from a second copy in configuration:
//
//   - GET /v1/projections/consumers/{consumer_id} gives reconciliation_interval_seconds, the age of the
//     last recorded run (reconciliation_age_seconds, absent until one has run) and
//     reconciliation_requested_at, which a restore bump sets;
//   - a run is due when none has been recorded, when a restore asked for one, or when the age plus one
//     check interval reaches the declared interval, so the run lands before the producer's
//     ReconciliationOverdueWarning, which fires past one interval;
//   - a due run sends projection.Report to POST /v1/projections/reconcile as this consumer, and the
//     repair arrives as projection.repair.reconciled through the ordinary delivery path.
//
// Prometheus: "The key metric of a batch job is the last time it succeeded." Driving the schedule from
// that recorded time, rather than from a timer in this process, means a restart, a second replica or a
// failed run cannot stretch the gap between recorded runs past the declared interval: whichever process
// checks next sees the age. Two replicas that check in the same instant both run, which the producer
// handles: a reconciliation is idempotent against a consistent state.
//
// The ages are the producer's, computed on its clock when it answers, so nothing here subtracts one
// clock from another.
package reconcile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-reference/internal/projection"
)

var (
	// ErrRefused is a 401 or 403 from the producer. Before organization-control 1.16.0 its reconcile
	// route admitted a provider alone and answered every consumer 403.
	ErrRefused = errors.New("reconcile: organization-control refused this consumer")

	// ErrNotRegistered is a 404 for this consumer's own registration.
	ErrNotRegistered = errors.New("reconcile: organization-control holds no registration for this consumer")
)

// Registration is the part of the consumer's own registration the schedule reads.
type Registration struct {
	IntervalSeconds int64      `json:"reconciliation_interval_seconds"`
	AgeSeconds      *int64     `json:"reconciliation_age_seconds"`
	RequestedAt     *time.Time `json:"reconciliation_requested_at"`
}

// Finding is the part of one finding the run logs.
type Finding struct {
	Classification string `json:"classification"`
	MembershipID   string `json:"membership_id"`
}

// Result is the producer's answer to one run.
type Result struct {
	Mark     int64     `json:"mark"`
	RunAt    time.Time `json:"run_at"`
	Findings []Finding `json:"findings"`
}

// Extra counts the findings of class extra: access this consumer projected that authority does not
// grant, which the producer treats as a security incident.
func (r Result) Extra() int {
	n := 0
	for _, f := range r.Findings {
		if f.Classification == "extra" {
			n++
		}
	}
	return n
}

// Client calls organization-control as this consumer.
type Client struct {
	base     string
	token    string
	consumer string
	http     *http.Client
}

// NewClient builds the client. The token is the consumer's own, the one the snapshot and the frontier
// are read with: the reconcile route admits a registered consumer for its own consumer_id.
func NewClient(baseURL, token, consumer string, timeout time.Duration) (*Client, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	parsed, err := url.Parse(trimmed)
	if trimmed == "" || err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("reconcile: %q is not an absolute URL", baseURL)
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("reconcile: a bearer token is required")
	}
	if strings.TrimSpace(consumer) == "" {
		return nil, errors.New("reconcile: the consumer name is required")
	}
	if timeout <= 0 {
		return nil, errors.New("reconcile: the timeout must be positive")
	}
	return &Client{base: trimmed, token: token, consumer: consumer, http: &http.Client{Timeout: timeout}}, nil
}

// Registration reads this consumer's own registration.
func (c *Client) Registration(ctx context.Context) (Registration, error) {
	var out Registration
	err := c.call(ctx, http.MethodGet, "/v1/projections/consumers/"+url.PathEscape(c.consumer), nil, &out)
	return out, err
}

// Reconcile sends one report.
func (c *Client) Reconcile(ctx context.Context, report projection.Report) (Result, error) {
	var out Result
	err := c.call(ctx, http.MethodPost, "/v1/projections/reconcile", report, &out)
	return out, err
}

func (c *Client) call(ctx context.Context, method, path string, body, into any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("reconcile: encoding the request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return fmt.Errorf("reconcile: building the request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("reconcile: reaching organization-control: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	switch {
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%w: %s %s answered %d", ErrRefused, method, path, response.StatusCode)
	case response.StatusCode == http.StatusNotFound:
		return fmt.Errorf("%w: %s %s answered 404", ErrNotRegistered, method, path)
	case response.StatusCode != http.StatusOK:
		detail, _ := io.ReadAll(io.LimitReader(response.Body, 1<<12))
		return fmt.Errorf("reconcile: %s %s answered %d: %s", method, path, response.StatusCode,
			strings.TrimSpace(string(detail)))
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<22)).Decode(into); err != nil {
		return fmt.Errorf("reconcile: decoding the answer to %s %s: %w", method, path, err)
	}
	return nil
}

// Due reports whether a run is due, and why. check is how often the schedule asks.
func Due(r Registration, check time.Duration) (bool, string) {
	switch {
	case r.RequestedAt != nil:
		return true, "a restore asked every consumer to reconcile"
	case r.AgeSeconds == nil:
		return true, "no reconciliation is recorded for this consumer"
	case r.IntervalSeconds <= 0:
		// organization-control always serves one from 60 to 604800. A registration without it is a
		// producer from before 1.16.0, which declares nothing to run against.
		return false, "the registration declares no reconciliation interval"
	}
	interval := time.Duration(r.IntervalSeconds) * time.Second
	age := time.Duration(*r.AgeSeconds) * time.Second
	if age+check >= interval {
		return true, fmt.Sprintf("the last run is %s old and the declared interval is %s", age, interval)
	}
	return false, ""
}

// Reporter is the projection's report.
type Reporter interface {
	Report(ctx context.Context) (projection.Report, error)
}

// Producer is organization-control as the schedule uses it.
type Producer interface {
	Registration(ctx context.Context) (Registration, error)
	Reconcile(ctx context.Context, report projection.Report) (Result, error)
}

// Outcome is what one check did.
type Outcome struct {
	Ran    bool
	Reason string
	Rows   int
	Result Result
}

// Scheduler checks the registration every Check and runs a reconciliation when one is due.
type Scheduler struct {
	Reporter Reporter
	Producer Producer
	Check    time.Duration
	Logger   *slog.Logger
}

// Tick checks once and runs when due.
func (s *Scheduler) Tick(ctx context.Context) (Outcome, error) {
	registration, err := s.Producer.Registration(ctx)
	if err != nil {
		return Outcome{}, err
	}
	due, reason := Due(registration, s.Check)
	if !due {
		return Outcome{Reason: reason}, nil
	}
	report, err := s.Reporter.Report(ctx)
	if err != nil {
		return Outcome{Reason: reason}, err
	}
	result, err := s.Producer.Reconcile(ctx, report)
	if err != nil {
		return Outcome{Reason: reason, Rows: len(report.Rows)}, err
	}
	return Outcome{Ran: true, Reason: reason, Rows: len(report.Rows), Result: result}, nil
}

// Run checks at once and then every Check until ctx ends. A failure is logged and the next check tries
// again; the producer's ReconciliationOverdue alerts are what report a consumer that keeps failing.
func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.Check)
	defer ticker.Stop()
	for {
		outcome, err := s.Tick(ctx)
		s.log(ctx, outcome, err)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Scheduler) log(ctx context.Context, outcome Outcome, err error) {
	switch {
	case err != nil && ctx.Err() != nil:
	case errors.Is(err, projection.ErrNotBootstrapped):
		s.Logger.Warn("reconciliation is due and this consumer has not bootstrapped; nothing to compare yet",
			slog.String("reason", outcome.Reason))
	case errors.Is(err, ErrRefused), errors.Is(err, ErrNotRegistered):
		s.Logger.Warn("organization-control refused this consumer's reconciliation; checked again at the next "+
			"interval, and an operator can reconcile as a provider meanwhile", slog.String("error", err.Error()))
	case err != nil:
		s.Logger.Error("the consumer's reconciliation failed", slog.String("error", err.Error()))
	case outcome.Ran:
		attrs := []slog.Attr{slog.String("reason", outcome.Reason), slog.Int64("mark", outcome.Result.Mark),
			slog.Int("rows", outcome.Rows), slog.Int("findings", len(outcome.Result.Findings)),
			slog.Int("extra", outcome.Result.Extra())}
		level := slog.LevelInfo
		switch {
		case outcome.Result.Extra() > 0:
			level = slog.LevelError
		case len(outcome.Result.Findings) > 0:
			level = slog.LevelWarn
		}
		s.Logger.LogAttrs(ctx, level, "the consumer reconciled itself with organization-control", attrs...)
	}
}
