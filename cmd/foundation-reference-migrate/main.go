// Command reference-migrate applies the platform schema this consumer depends on, then its
// own projection schema.
//
// Two sources, one job, in this order: foundation-platform owns platform.processed_event —
// the table inbox.Guard writes — and this repository owns projection.membership. Copying the
// platform DDL here would fork it, and a forked deduplication table is a consumer that
// silently stops deduplicating after a substrate upgrade.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	platform "github.com/anshacerbia2/foundation-platform/migrations"

	"github.com/anshacerbia2/foundation-reference/internal/projection"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("migration failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	// -rebuild is a deliberate act, not a default. It drops the projection, after which the consumer
	// holds no positive authority and refuses every projection-backed operation until it has taken a
	// snapshot and caught up -- correct behaviour, and a catastrophic thing to do on every deploy.
	rebuild := flag.Bool("rebuild", false,
		"drop the projection first, so it can be rebuilt from a snapshot")
	flag.Parse()

	dsn := os.Getenv("REFERENCE_MIGRATION_DATABASE_URL")
	if dsn == "" {
		return errors.New("REFERENCE_MIGRATION_DATABASE_URL is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	pool, err := db.Open(ctx, db.Config{Name: "reference-migrate", DSN: dsn, MaxConns: 2})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer pool.Close()

	// PlatformMigrations already returns them in application order, derived from the file
	// names rather than from a manifest. Re-sorting here would be a second ordering rule
	// that could disagree with the substrate's.
	if *rebuild {
		if err := exec(ctx, pool, projection.Rebuild); err != nil {
			return fmt.Errorf("dropping the projection: %w", err)
		}
		logger.Warn("projection dropped; it holds no positive authority until it has bootstrapped",
			slog.String("source", "projection/rebuild.sql"))
	}

	migrations, err := platform.PlatformMigrations()
	if err != nil {
		return fmt.Errorf("reading the platform set: %w", err)
	}

	for _, migration := range migrations {
		if err := exec(ctx, pool, migration.SQL); err != nil {
			return fmt.Errorf("applying %s: %w", migration.Name, err)
		}
		logger.Info("applied", slog.String("source", "foundation-platform"), slog.String("migration", migration.Name))
	}

	if err := exec(ctx, pool, projection.Schema); err != nil {
		return fmt.Errorf("applying the projection schema: %w", err)
	}
	logger.Info("applied", slog.String("source", "projection/schema.sql"))

	return nil
}

func exec(ctx context.Context, pool *db.Pool, statements string) error {
	return pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, statements)
		return err
	})
}
