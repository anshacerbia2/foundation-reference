package projection

// The consumer's account of its own projection, for organization-control's reconciliation.
//
// The consumer reconciles itself (ADR-ORG-001 §5.7, amended 2026-10-20): it sends this report to
// POST /v1/projections/reconcile, the authority compares it with what it grants, and the repair
// arrives as projection.repair.reconciled (repair.go). The report states the active Memberships held
// here and the position they correspond to, in the reconcile route's shape.

import (
	"context"
	"fmt"

	"github.com/anshacerbia2/foundation-platform/db"
)

// ReportedRow is one Membership this consumer holds active.
type ReportedRow struct {
	MembershipID      string `json:"membership_id"`
	MembershipVersion int64  `json:"membership_version"`
}

// Report is the reconcile route's body: {"consumer_id", "mark", "rows"}.
type Report struct {
	ConsumerID string        `json:"consumer_id"`
	Mark       int64         `json:"mark"`
	Rows       []ReportedRow `json:"rows"`
}

// One statement, so the mark and the rows are read from one snapshot of the database even under READ
// COMMITTED: a delivery committing between two statements would otherwise put a row in the report that
// its mark does not cover. The watermark row drives the read, so a consumer with no watermark returns
// nothing at all, and the LEFT JOIN keeps a bootstrapped consumer that holds no active Membership.
const reportStatement = `SELECT w.snapshot_mark, w.applied_mark, m.membership_id::text, m.membership_version
  FROM projection.watermark w
  LEFT JOIN projection.membership m ON m.membership_status = 'active'
 WHERE w.consumer = $1
 ORDER BY m.membership_id`

// Report reads this consumer's active Memberships and the position they correspond to: the higher of
// the snapshot mark and the highest applied position. A consumer that has not bootstrapped has nothing
// to compare, and reports ErrNotBootstrapped instead: its projection is not a copy of authority yet,
// and the producer refuses a report without a positive mark.
func (p *Projector) Report(ctx context.Context) (Report, error) {
	report := Report{ConsumerID: p.consumer, Rows: []ReportedRow{}}
	bootstrapped := false
	err := p.pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, reportStatement, p.consumer)
		if err != nil {
			return fmt.Errorf("projection: reading the report: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				snapshotMark *int64
				appliedMark  int64
				membership   *string
				version      *int64
			)
			if err := rows.Scan(&snapshotMark, &appliedMark, &membership, &version); err != nil {
				return fmt.Errorf("projection: scanning the report: %w", err)
			}
			if snapshotMark == nil {
				return nil
			}
			bootstrapped = true
			report.Mark = max(*snapshotMark, appliedMark)
			if membership != nil && version != nil {
				report.Rows = append(report.Rows, ReportedRow{MembershipID: *membership, MembershipVersion: *version})
			}
		}
		return rows.Err()
	})
	if err != nil {
		return Report{}, err
	}
	if !bootstrapped {
		return Report{}, ErrNotBootstrapped
	}
	return report, nil
}
