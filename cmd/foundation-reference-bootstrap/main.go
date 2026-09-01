// Command foundation-reference-bootstrap takes a snapshot from organization-control and seeds this
// consumer's projection from it.
//
// # Why it is a separate command
//
// Bootstrapping is a deliberate act with a visible outcome, not a step the service performs while
// starting. A consumer that snapshotted on every boot would take a fresh snapshot after every deploy
// — hiding the one state the bootstrap contract exists to make visible, which is a consumer holding a
// model it never seeded and therefore holding authority over nothing.
//
// Until this has run, every projection-backed enforcement check refuses. That is correct rather than
// unfortunate: the consumer has no positive authority to report.
//
// # The contract it honours
//
// Pages are seeded at the snapshot's mark, never at each row's own position, and the mark is recorded
// only when the last page has been applied. Then the catch-up events — everything the dispatcher
// delivers after that mark — are applied by version comparison rather than discarded at the mark,
// because organization-control's sequence is allocated at INSERT rather than at COMMIT: a row can be
// invisible to the snapshot while carrying a position below the mark, and discarding at the mark would
// discard the only event that would ever deliver it.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	fdb "github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/foundation-reference/internal/projection"
)

const deployable = "foundation-reference-bootstrap"

type snapshotRow struct {
	MembershipID id.UUID  `json:"membership_id"`
	PrincipalID  id.UUID  `json:"principal_id"`
	TenantID     id.UUID  `json:"tenant_id"`
	WorkspaceID  *id.UUID `json:"workspace_id"`

	MembershipStatus  string `json:"membership_status"`
	MembershipVersion int64  `json:"membership_version"`

	TenantStatus          string `json:"tenant_status"`
	TenantSecurityVersion int64  `json:"tenant_security_version"`
}

type snapshotPage struct {
	HighWaterMark int64         `json:"high_water_mark"`
	TakenAt       time.Time     `json:"taken_at"`
	Rows          []snapshotRow `json:"rows"`
	Cursor        string        `json:"cursor"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("bootstrap failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	dsn := strings.TrimSpace(os.Getenv("REFERENCE_DATABASE_URL"))
	authority := strings.TrimRight(strings.TrimSpace(os.Getenv("REFERENCE_AUTHORITY_BASE_URL")), "/")
	token := strings.TrimSpace(os.Getenv("REFERENCE_AUTHORITY_TOKEN"))
	consumer := strings.TrimSpace(os.Getenv("REFERENCE_CONSUMER_NAME"))

	var problems []error
	if dsn == "" {
		problems = append(problems, errors.New("REFERENCE_DATABASE_URL is required"))
	}
	if authority == "" {
		problems = append(problems, errors.New("REFERENCE_AUTHORITY_BASE_URL is required"))
	}
	if token == "" {
		problems = append(problems, errors.New("REFERENCE_AUTHORITY_TOKEN is required"))
	}
	if consumer == "" {
		problems = append(problems, errors.New("REFERENCE_CONSUMER_NAME is required"))
	}
	if len(problems) > 0 {
		return errors.Join(problems...)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	pool, err := fdb.Open(ctx, fdb.Config{Name: deployable, DSN: dsn, MaxConns: 2})
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer pool.Close()

	projector, err := projection.New(pool, consumer)
	if err != nil {
		return fmt.Errorf("projector: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	var (
		cursor string
		mark   int64
		pages  int
		seeded int
	)

	for {
		page, err := fetchPage(ctx, client, authority, token, consumer, cursor, mark)
		if err != nil {
			return err
		}
		pages++

		if mark == 0 {
			mark = page.HighWaterMark
		} else if page.HighWaterMark != mark {
			// Every page of one snapshot carries one mark. A page reporting a different one means the
			// continuation was not accepted as a continuation, and seeding it would mix two instants
			// into one model.
			return fmt.Errorf("page %d reports mark %d, and the snapshot began at %d",
				pages, page.HighWaterMark, mark)
		}

		rows := make([]projection.Seeded, 0, len(page.Rows))
		for _, row := range page.Rows {
			// A snapshot carries only active memberships, and the Tenant's own status travels with
			// each row for a reason: an active membership inside a suspended Tenant grants nothing.
			// Seeded as suspended rather than dropped, so the consumer holds the row and can be
			// corrected by a later event instead of treating the principal as never seen.
			status := projection.Status(row.MembershipStatus)
			if row.TenantStatus != "active" {
				status = projection.Suspended
			}
			rows = append(rows, projection.Seeded{
				MembershipID:          row.MembershipID,
				TenantID:              row.TenantID,
				PrincipalID:           row.PrincipalID,
				WorkspaceID:           row.WorkspaceID,
				Status:                status,
				Version:               row.MembershipVersion,
				TenantSecurityVersion: row.TenantSecurityVersion,
			})
		}

		final := page.Cursor == ""
		if err := projector.Seed(ctx, rows, mark, final); err != nil {
			return fmt.Errorf("seeding page %d: %w", pages, err)
		}
		seeded += len(rows)

		logger.Info("page applied",
			slog.Int("page", pages),
			slog.Int("rows", len(rows)),
			slog.Int64("mark", mark),
			slog.Bool("final", final))

		if final {
			break
		}
		cursor = page.Cursor
	}

	position, err := projector.Position(ctx)
	if err != nil {
		return fmt.Errorf("reading the recorded position: %w", err)
	}
	if position.SnapshotMark == nil {
		return errors.New("the snapshot completed and no mark was recorded")
	}

	logger.Info("bootstrapped",
		slog.Int("pages", pages),
		slog.Int("memberships", seeded),
		slog.Int64("snapshot_mark", *position.SnapshotMark))
	return nil
}

func fetchPage(ctx context.Context, client *http.Client,
	authority, token, consumer, cursor string, mark int64) (snapshotPage, error) {
	body := map[string]any{"consumer_id": consumer, "page_size": 500}
	if cursor != "" {
		body["cursor"] = cursor
		// Required with a cursor. Continuing without it is refused rather than re-derived, because a
		// re-derived mark would be a second instant silently stitched into one snapshot.
		body["mark"] = mark
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		return snapshotPage{}, fmt.Errorf("encoding the snapshot request: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		authority+"/v1/projections/snapshot", strings.NewReader(string(encoded)))
	if err != nil {
		return snapshotPage{}, fmt.Errorf("building the snapshot request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)

	response, err := client.Do(request)
	if err != nil {
		return snapshotPage{}, fmt.Errorf("reaching the authority: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(response.Body, 1<<12))
		return snapshotPage{}, fmt.Errorf("the authority answered %d: %s",
			response.StatusCode, strings.TrimSpace(string(detail)))
	}

	var page snapshotPage
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<22)).Decode(&page); err != nil {
		return snapshotPage{}, fmt.Errorf("decoding the snapshot page: %w", err)
	}
	if page.HighWaterMark <= 0 {
		return snapshotPage{}, errors.New("the snapshot page carries no high water mark")
	}
	return page, nil
}
