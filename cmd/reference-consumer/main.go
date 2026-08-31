// Command reference-consumer is the enforcing consumer for Proof A.
//
// It exists to answer one question with evidence: does a membership revocation in
// organization-control become a refused operation in a different process, within a delay
// that can be measured? Everything here is the smallest arrangement that makes that
// question answerable — an intake, a projection, and four operations whose security classes
// differ in exactly one respect, what they do when the projection cannot answer.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/anshacerbia2/foundation-platform/db"
	fhttp "github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/observability"

	"github.com/anshacerbia2/reference-consumer/internal/config"
	"github.com/anshacerbia2/reference-consumer/internal/httpapi"
	"github.com/anshacerbia2/reference-consumer/internal/projection"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(ctx, logger); err != nil {
		logger.Error("exiting", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}

	telemetry, err := observability.New(observability.Config{
		Deployable: config.Deployable,
		System:     config.System,
		Logger:     logger,
	})
	if err != nil {
		return fmt.Errorf("telemetry: %w", err)
	}

	pool, err := db.Open(ctx, db.Config{
		Name: config.Deployable, DSN: cfg.DatabaseURL, MaxConns: 10,
	})
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer pool.Close()

	projector, err := projection.New(pool, cfg.ConsumerName)
	if err != nil {
		return fmt.Errorf("projector: %w", err)
	}

	// A nil authority is a valid deployment, not a defect: LOW_RISK traffic is still
	// servable. The two classes that need it are refused with a reason naming the absence,
	// which is the correct answer to "I cannot check".
	var authority httpapi.Authority
	if cfg.AuthorityBaseURL != "" {
		authority, err = httpapi.NewAuthorityClient(cfg.AuthorityBaseURL, cfg.AuthorityTimeout)
		if err != nil {
			return fmt.Errorf("authority client: %w", err)
		}
	} else {
		logger.Warn("no authority configured; PRIVILEGED and IRREVERSIBLE operations will be refused",
			slog.String("variable", "REFERENCE_AUTHORITY_BASE_URL"))
	}

	enforcer, err := httpapi.NewEnforcer(projector, authority, cfg.MaxProjectionAge)
	if err != nil {
		return fmt.Errorf("enforcer: %w", err)
	}

	surface, err := httpapi.Routes(httpapi.Config{
		Projector: projector,
		Enforcer:  enforcer,
		Telemetry: telemetry,
	})
	if err != nil {
		return fmt.Errorf("routes: %w", err)
	}

	// Probes are never wrapped by the API chain: one chain over everything is how
	// identity-control answered 401 on /readyz and no replica entered service.
	probeChain := func(next http.Handler) http.Handler { return next }
	apiChain := fhttp.Chain(fhttp.Options{
		Telemetry:   telemetry,
		Timeout:     cfg.HTTPRequestTimeout,
		MaxInFlight: cfg.HTTPMaxInFlight,
	})

	server, err := fhttp.NewServer(cfg.ListenAddress, surface.Mount(probeChain, apiChain), fhttp.ServerConfig{
		ReadTimeout:  cfg.HTTPReadTimeout,
		WriteTimeout: cfg.HTTPWriteTimeout,
	})
	if err != nil {
		return fmt.Errorf("http server: %w", err)
	}

	// Bind before logging "listening". ListenAndServe binds and serves in one call, so the
	// log line would precede the bind and a port conflict would produce a startup log that
	// says the service is up when it never came up.
	listener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("bind %s: %w", cfg.ListenAddress, err)
	}
	logger.Info("listening",
		slog.String("address", listener.Addr().String()),
		slog.String("consumer", cfg.ConsumerName),
		slog.Duration("max_projection_age", cfg.MaxProjectionAge))

	serveErr := make(chan error, 1)
	go func() {
		if listenErr := server.Serve(listener); listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
			serveErr <- listenErr
			return
		}
		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		if err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	case <-ctx.Done():
		logger.Info("shutdown signalled", slog.Duration("grace", cfg.HTTPShutdownGrace))
	}

	// A fresh context: reusing the cancelled one would abort the drain at the instant it
	// began, which is indistinguishable from having no grace period.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTPShutdownGrace)
	defer cancel()
	if err := fhttp.Shutdown(shutdownCtx, server, cfg.HTTPShutdownGrace); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return <-serveErr
}
