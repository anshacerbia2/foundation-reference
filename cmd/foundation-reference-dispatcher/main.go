// Command foundation-reference-dispatcher drains organization-control's outbox to a consumer.
//
// # Why it is a separate process
//
// The API and the delivery worker fail differently and are restarted for different reasons. Run
// inside the API, a deploy stops delivery; run beside it, a delivery backlog competes with request
// handling for the same connection pool. Separate, the lag has its own lifecycle and its own
// metric, and the outbox stays owned by organization-control either way — this process holds a
// database credential, not authority.
//
// # Why it is in this repository
//
// It publishes over HTTP, and ADR-ORG-001 §5.4 gives organization-control no outbound HTTP route.
// archcheck refuses the import there, and that refusal is correct: the prohibition exists so the
// control plane cannot grow a client to another domain. When the transport becomes a broker client
// this process can move into organization-control, which is where it belongs once it no longer
// makes HTTP calls.
//
// # What it may do to the database
//
// It authenticates as a login role inheriting `organization_dispatch_rt`: SELECT and UPDATE on
// `platform.outbox`, SELECT/INSERT/UPDATE on `platform.dead_letter`, and nothing else. Not the
// provider role — a delivery worker that could mutate every Tenant in the estate would be a second
// process with the control plane's authority, for a job whose whole scope is moving rows that are
// already committed.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	fdb "github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/observability"
	"github.com/anshacerbia2/foundation-platform/outbox"

	"github.com/anshacerbia2/foundation-reference/internal/dispatch"
)

const (
	deployable = "foundation-reference-dispatcher"
	system     = "SAD-004"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", deployable, err)
		os.Exit(1)
	}
}

func run() error {
	dsn := strings.TrimSpace(os.Getenv("DISPATCH_OUTBOX_DATABASE_URL"))
	endpoint := strings.TrimSpace(os.Getenv("DISPATCH_CONSUMER_ENDPOINT"))
	token := strings.TrimSpace(os.Getenv("DISPATCH_DELIVERY_TOKEN"))

	var problems []error
	if dsn == "" {
		problems = append(problems, errors.New("DISPATCH_OUTBOX_DATABASE_URL is required"))
	}
	if endpoint == "" {
		problems = append(problems, errors.New("DISPATCH_CONSUMER_ENDPOINT is required"))
	}
	if token == "" {
		// Refused here rather than discovered per delivery. Sent unauthenticated, every event
		// would dead-letter after its attempts ran out, and the cause would look like a consumer
		// fault.
		problems = append(problems, errors.New("DISPATCH_DELIVERY_TOKEN is required"))
	}
	if len(problems) > 0 {
		return errors.Join(problems...)
	}

	timeout := durationOr("DISPATCH_PUBLISH_TIMEOUT", 5*time.Second)
	interval := durationOr("DISPATCH_INTERVAL", 500*time.Millisecond)
	idle := durationOr("DISPATCH_IDLE_INTERVAL", 5*time.Second)

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// Signals first: a process that acquires a database connection before it can be interrupted
	// ignores the first SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	telemetry, err := observability.New(observability.Config{
		Deployable: deployable,
		System:     system,
		Logger:     logger,
	})
	if err != nil {
		return fmt.Errorf("telemetry: %w", err)
	}

	// Few connections on purpose. The worker counts below bound the concurrency, and a pool larger
	// than they can use is a pool that competes with the API for the same server's connection slots
	// while sitting idle.
	pool, err := fdb.Open(ctx, fdb.Config{Name: deployable, DSN: dsn, MaxConns: 4})
	if err != nil {
		return fmt.Errorf("outbox database: %w", err)
	}
	defer pool.Close()

	publisher, err := dispatch.NewHTTPPublisher(endpoint, token, timeout, telemetry)
	if err != nil {
		return fmt.Errorf("publisher: %w", err)
	}

	dispatcher, err := outbox.NewDispatcher(pool, publisher, outbox.Config{
		Interval:     interval,
		IdleInterval: idle,
	})
	if err != nil {
		return fmt.Errorf("dispatcher: %w", err)
	}

	logger.Info("dispatching",
		slog.String("consumer", endpoint),
		slog.Duration("interval", interval),
		slog.Duration("idle_interval", idle),
		slog.Duration("publish_timeout", timeout))

	// Run returns when the context is cancelled, so a SIGTERM drains the in-flight batch rather
	// than abandoning rows mid-publication: a row abandoned after publication and before its
	// bookkeeping is the duplicate the consumer's inbox exists to absorb, and producing one on
	// every deploy would make that safety net load-bearing for routine operations.
	if err := dispatcher.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("run: %w", err)
	}

	logger.Info("stopped")
	return nil
}

func durationOr(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return value
}
