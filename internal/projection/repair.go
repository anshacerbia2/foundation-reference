package projection

// Applying a reconciliation sweep's repairs (organization-control ROADMAP item 19).
//
// organization-control compares what this consumer reported against authority and publishes one
// projection.repair.reconciled event per sweep that found something. Each finding carries the
// authoritative Membership, in the shape of a Membership event's payload, or null when authority
// never granted it. Its findings used to carry versions alone, which nothing can apply, so this
// consumer refused the event as poison and every repair dead-lettered.

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/event"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/inbox"
)

// RepairReconciled is the sweep's event type.
const RepairReconciled event.Type = "com.scnehaux.organization.projection.repair.reconciled"

// RepairPayload is the subset of a sweep this consumer reads.
type RepairPayload struct {
	ConsumerID string          `json:"consumer_id"`
	Mark       int64           `json:"mark"`
	Findings   []RepairFinding `json:"findings"`
}

// RepairFinding is one difference and the state that repairs it.
type RepairFinding struct {
	Classification string   `json:"classification"`
	MembershipID   id.UUID  `json:"membership_id"`
	State          *Payload `json:"state"`
}

// removeStatement drops a row authority never granted. No version guard: a Membership that does not
// exist in authority has no later event that could be overtaken.
const removeStatement = `DELETE FROM projection.membership WHERE membership_id = $1`

var repairStatuses = map[string]Status{"active": Active, "suspended": Suspended, "revoked": Revoked}

// applyRepair applies one sweep in one transaction with its inbox guard.
//
// A state is applied by the rule every Membership event is: a higher version replaces a lower one. A
// sweep that arrives after a newer event therefore changes nothing for that Membership, and a consumer
// ahead of authority is not rolled back. That case is a corruption the sweep keeps reporting, not one
// to repair silently. A sweep for another consumer is acknowledged: its findings describe that
// consumer's report, not this one's.
func (p *Projector) applyRepair(ctx context.Context, envelope event.Envelope) (Outcome, error) {
	if envelope.StreamPosition <= 0 {
		return Outcome{}, fmt.Errorf("%w: the envelope carries no stream position", ErrMalformed)
	}
	var payload RepairPayload
	if err := json.Unmarshal(envelope.Data, &payload); err != nil {
		return Outcome{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if payload.ConsumerID != p.consumer {
		return p.acknowledge(ctx, envelope)
	}
	for _, f := range payload.Findings {
		if f.MembershipID.IsNil() {
			return Outcome{}, fmt.Errorf("%w: a finding names no membership", ErrMalformed)
		}
		if f.State == nil {
			// Null means "authority never granted this", which only an extra can say. A missing or
			// mismatch finding without a state is a producer that predates the state and sent
			// versions alone. Reading its null as a removal would delete a Membership authority
			// holds, so the sweep is refused as a whole instead.
			if f.Classification != "extra" {
				return Outcome{}, fmt.Errorf("%w: a %s finding for %s carries no state", ErrMalformed,
					f.Classification, f.MembershipID)
			}
			continue
		}
		if f.State.MembershipID != f.MembershipID || f.State.TenantID.IsNil() || f.State.PrincipalID.IsNil() ||
			f.State.Version <= 0 {
			return Outcome{}, fmt.Errorf("%w: the state for %s is incomplete", ErrMalformed, f.MembershipID)
		}
		if _, ok := repairStatuses[f.State.Status]; !ok {
			return Outcome{}, fmt.Errorf("%w: %q is not a membership status", ErrMalformed, f.State.Status)
		}
	}

	var outcome Outcome
	err := p.pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		first, err := inbox.Guard(ctx, tx, p.consumer, envelope.ID, envelope.Type)
		if err != nil {
			return err
		}
		if !first {
			outcome.Duplicate = true
			return nil
		}

		appliedAt := p.now().UTC()
		for _, f := range payload.Findings {
			if f.State == nil {
				if _, err := tx.Exec(ctx, removeStatement, f.MembershipID.String()); err != nil {
					return fmt.Errorf("projection: removing %s: %w", f.MembershipID, err)
				}
				continue
			}
			s := f.State
			if _, err := tx.Exec(ctx, upsertStatement,
				s.MembershipID.String(), s.TenantID.String(), s.PrincipalID.String(), s.workspace(),
				string(repairStatuses[s.Status]), s.Version, envelope.StreamPosition,
				s.TenantSecurityVersion, appliedAt, envelope.ID.String()); err != nil {
				return fmt.Errorf("projection: repairing %s: %w", f.MembershipID, err)
			}
		}
		if _, err := tx.Exec(ctx, advanceWatermark, p.consumer, envelope.StreamPosition, appliedAt); err != nil {
			return fmt.Errorf("projection: advancing the watermark: %w", err)
		}
		outcome.Applied = true
		return nil
	})
	if err != nil {
		return Outcome{}, err
	}
	return outcome, nil
}
