// Package projection holds this consumer's replica of Membership authority and answers the one
// question an enforcing consumer has: may this principal act in this tenant, and how much do we
// trust that answer.
//
// # Positive state, not a deny-list
//
// The first version projected revocations only. That made an absent row mean two different things —
// "holds an active membership" and "was never a member" — so absence had to be treated as permission,
// and every enforcement answer was the absence of bad news rather than the presence of authority.
// This version projects status, seeded by a snapshot, so absence means no positive authority and the
// answer is a refusal.
//
// # Two orderings, and only one of them is the version
//
// `membership_version` is monotonic per membership and says nothing across memberships. A principal
// may hold membership A, have it revoked at version 5, and be granted membership B at version 1 in
// the same tenant: comparing 1 against 5 discards the grant and leaves the revocation standing
// forever.
//
// So the rule is explicit:
//
//	same membership_id      -> compare membership_version
//	different membership_id -> compare the producer's stream position
//
// The stream position is the authority's own commit order, which is the only total order both sides
// agree on. TestANewMembershipIsNotOlderThanTheRevokedOneItReplaces is the assertion.
//
// # Duplicate delivery
//
// inbox.Guard registers the event inside the same transaction that applies it. Registered separately,
// a crash between them marks an event processed whose effect rolled back — and the redelivery that
// would have fixed it is discarded as a duplicate.
package projection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/event"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/inbox"
)

// The four event types that change Membership authority. Two lifecycle, two security, and the
// distinction is the producer's: urgency is not derived from the resulting state, because active via
// grant and active via restore are not the same event.
const (
	MembershipGranted   event.Type = "com.scnehaux.organization.membership.lifecycle.granted"
	MembershipRestored  event.Type = "com.scnehaux.organization.membership.lifecycle.restored"
	MembershipSuspended event.Type = "com.scnehaux.organization.membership.security.suspended"
	MembershipRevoked   event.Type = "com.scnehaux.organization.membership.security.revoked"
)

// Status is projected membership state.
type Status string

const (
	Active    Status = "active"
	Suspended Status = "suspended"
	Revoked   Status = "revoked"
)

var (
	ErrNoPool          = errors.New("projection: a pool is required")
	ErrNoConsumer      = errors.New("projection: a consumer name is required")
	ErrUnknownType     = errors.New("projection: event type is not one this consumer applies")
	ErrMalformed       = errors.New("projection: payload does not carry the members this consumer needs")
	ErrNotProjected    = errors.New("projection: no membership is projected for this tenant and principal")
	ErrNotBootstrapped = errors.New("projection: this consumer has taken no snapshot, so it holds no positive authority")
)

// statusFor maps an event type to the state it produces. A type absent here is refused rather than
// ignored: a consumer that silently skips an unrecognised type reports success for work it never did,
// and the dispatcher marks the row published.
var statusFor = map[event.Type]Status{
	MembershipGranted:   Active,
	MembershipRestored:  Active,
	MembershipSuspended: Suspended,
	MembershipRevoked:   Revoked,
}

// Payload is the subset of the producer's event this consumer reads.
//
// The names are the producer's, read from a real envelope rather than assumed: the field is
// membership_version, and calling it "version" here made this consumer refuse every real event as
// malformed while its own tests passed. testdata/ holds the envelope that proved it.
type Payload struct {
	MembershipID id.UUID `json:"membership_id"`
	TenantID     id.UUID `json:"tenant_id"`
	PrincipalID  id.UUID `json:"principal_id"`
	Version      int64   `json:"membership_version"`

	// Status as the producer sees it. Read but not trusted over the event type: a granted event
	// carrying "revoked" is a contradiction, and the type is the thing the dispatcher routed on.
	Status string `json:"membership_status"`

	TenantSecurityVersion int64 `json:"tenant_security_version"`
}

// Record is what an enforcement decision reads.
type Record struct {
	MembershipID          id.UUID
	TenantID              id.UUID
	PrincipalID           id.UUID
	Status                Status
	Version               int64
	TenantSecurityVersion int64
	AppliedMark           int64
	AppliedAt             time.Time
}

// Active reports whether this record confers authority. A method rather than a comparison at each
// call site, so "which statuses are permissive" is decided in one place.
func (r Record) Active() bool { return r.Status == Active }

// Outcome reports what applying one delivery did, so the caller can distinguish the three cases that
// look identical from outside: applied, already seen, and superseded.
type Outcome struct {
	Applied    bool
	Duplicate  bool
	Superseded bool
	Record     Record
}

// Position is what this consumer knows about its own place in the producer's stream.
type Position struct {
	// SnapshotMark is nil until a snapshot completes. Nil means no positive authority for anything.
	SnapshotMark *int64

	// AppliedMark is the highest stream position applied since the snapshot.
	//
	// A lag metric, NOT a proof of convergence. The outbox allocates sequence values before commit,
	// so a rolled-back transaction consumes a value no event will ever carry: gaps below this mark
	// are expected, and a contiguous frontier cannot be derived from it. Convergence has to come
	// from the producer, which is the only side that knows which rows remain unpublished.
	AppliedMark int64

	BootstrappedAt *time.Time
}

type Projector struct {
	pool     *db.Pool
	consumer string
	now      func() time.Time
}

func New(pool *db.Pool, consumer string) (*Projector, error) {
	if pool == nil {
		return nil, ErrNoPool
	}
	if consumer == "" {
		return nil, ErrNoConsumer
	}
	return &Projector{pool: pool, consumer: consumer, now: time.Now}, nil
}

// The ordering rule, in SQL, and it is the whole reason broker ordering is not a correctness
// requirement.
//
// The WHERE clause admits the incoming row when either:
//
//   - it names the membership already stored and carries a higher membership_version, or
//   - it names a different membership and was committed later in the producer's stream.
//
// The second half is what lets a fresh grant replace a revoked membership. Written as one predicate
// rather than two statements because a read-then-write would race two deliveries for the same pair.
const upsertStatement = `INSERT INTO projection.membership
    (tenant_id, principal_id, membership_id, membership_status, membership_version,
     applied_mark, tenant_security_version, applied_at, event_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (tenant_id, principal_id) DO UPDATE
   SET membership_id           = excluded.membership_id,
       membership_status       = excluded.membership_status,
       membership_version      = excluded.membership_version,
       applied_mark            = excluded.applied_mark,
       tenant_security_version = excluded.tenant_security_version,
       applied_at              = excluded.applied_at,
       event_id                = excluded.event_id
 WHERE (excluded.membership_id = membership.membership_id
        AND excluded.membership_version > membership.membership_version)
    OR (excluded.membership_id <> membership.membership_id
        AND excluded.applied_mark > membership.applied_mark)`

// Advancing inserts when absent so a consumer that has applied an event but not bootstrapped still
// has a position -- and its NULL snapshot_mark is what refuses it authority.
const advanceWatermark = `INSERT INTO projection.watermark (consumer, applied_mark, updated_at)
VALUES ($1, $2, $3)
ON CONFLICT (consumer) DO UPDATE
   SET applied_mark = greatest(watermark.applied_mark, excluded.applied_mark),
       updated_at   = excluded.updated_at`

// Apply projects one delivery. Safe to call with the same envelope any number of times, in any order
// relative to other envelopes.
func (p *Projector) Apply(ctx context.Context, envelope event.Envelope) (Outcome, error) {
	status, known := statusFor[envelope.Type]
	if !known {
		return Outcome{}, fmt.Errorf("%w: %s", ErrUnknownType, envelope.Type)
	}
	if envelope.StreamPosition <= 0 {
		// The mark orders events across memberships, so an envelope without one cannot be placed.
		// A published envelope always carries it; one that does not was never dispatched.
		return Outcome{}, fmt.Errorf("%w: the envelope carries no stream position", ErrMalformed)
	}

	var payload Payload
	if err := json.Unmarshal(envelope.Data, &payload); err != nil {
		return Outcome{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if payload.MembershipID.IsNil() || payload.TenantID.IsNil() || payload.PrincipalID.IsNil() {
		return Outcome{}, fmt.Errorf("%w: membership_id, tenant_id and principal_id are required", ErrMalformed)
	}
	if payload.Version <= 0 {
		return Outcome{}, fmt.Errorf("%w: a positive membership_version is required", ErrMalformed)
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
		tag, err := tx.Exec(ctx, upsertStatement,
			payload.TenantID.String(), payload.PrincipalID.String(), payload.MembershipID.String(),
			string(status), payload.Version, envelope.StreamPosition,
			payload.TenantSecurityVersion, appliedAt, envelope.ID.String())
		if err != nil {
			return fmt.Errorf("projection: applying %s: %w", envelope.ID, err)
		}

		// The watermark advances whether or not the row was superseded: the delivery was seen, and a
		// lag metric that ignored superseded deliveries would report a consumer as further behind
		// than it is.
		if _, err := tx.Exec(ctx, advanceWatermark, p.consumer, envelope.StreamPosition, appliedAt); err != nil {
			return fmt.Errorf("projection: advancing the watermark: %w", err)
		}

		if tag.RowsAffected() == 0 {
			// The ordering rule refused it: either a higher version for the same membership, or a
			// later commit for a different one. Accounted for, and nothing regressed.
			outcome.Superseded = true
			return nil
		}

		outcome.Applied = true
		outcome.Record = Record{
			MembershipID:          payload.MembershipID,
			TenantID:              payload.TenantID,
			PrincipalID:           payload.PrincipalID,
			Status:                status,
			Version:               payload.Version,
			TenantSecurityVersion: payload.TenantSecurityVersion,
			AppliedMark:           envelope.StreamPosition,
			AppliedAt:             appliedAt,
		}
		return nil
	})
	if err != nil {
		return Outcome{}, err
	}
	return outcome, nil
}

const lookupStatement = `SELECT membership_id, membership_status, membership_version,
       tenant_security_version, applied_mark, applied_at
  FROM projection.membership WHERE tenant_id = $1 AND principal_id = $2`

// Lookup answers from the projection alone, keyed by the pair enforcement asks about.
//
// ErrNotProjected now means "no positive authority is projected for this pair" rather than "no
// revocation is recorded". That is the difference between an enforcement answer and the absence of
// bad news.
func (p *Projector) Lookup(ctx context.Context, tenantID, principalID id.UUID) (Record, error) {
	record := Record{TenantID: tenantID, PrincipalID: principalID}

	err := p.pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		// Query and Next rather than QueryRow: absence is an expected answer, and telling it apart
		// from a scan failure through QueryRow means comparing against the driver's sentinel. "No
		// authority is projected" and "the read broke" must reach the caller as different things —
		// the first is a refusal, the second is never fail-open eligible.
		rows, err := tx.Query(ctx, lookupStatement, tenantID.String(), principalID.String())
		if err != nil {
			return fmt.Errorf("projection: reading (%s, %s): %w", tenantID, principalID, err)
		}
		defer rows.Close()

		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return fmt.Errorf("projection: reading (%s, %s): %w", tenantID, principalID, err)
			}
			return ErrNotProjected
		}

		var membership, status string
		if err := rows.Scan(&membership, &status, &record.Version,
			&record.TenantSecurityVersion, &record.AppliedMark, &record.AppliedAt); err != nil {
			return fmt.Errorf("projection: scanning (%s, %s): %w", tenantID, principalID, err)
		}
		parsed, err := id.Parse(membership)
		if err != nil {
			return fmt.Errorf("projection: stored membership_id is not a UUID: %w", err)
		}
		record.MembershipID = parsed
		record.Status = Status(status)
		return nil
	})
	if err != nil {
		return Record{}, err
	}
	return record, nil
}

const positionStatement = `SELECT snapshot_mark, applied_mark, bootstrapped_at
  FROM projection.watermark WHERE consumer = $1`

// Position reports what this consumer knows about its place in the producer's stream.
func (p *Projector) Position(ctx context.Context) (Position, error) {
	var position Position
	err := p.pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, positionStatement, p.consumer)
		if err != nil {
			return fmt.Errorf("projection: reading the watermark: %w", err)
		}
		defer rows.Close()

		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return fmt.Errorf("projection: reading the watermark: %w", err)
			}
			// No row means this consumer has never applied anything and never bootstrapped. The zero
			// Position is the honest answer: no snapshot mark, no applied mark.
			return nil
		}
		return rows.Scan(&position.SnapshotMark, &position.AppliedMark, &position.BootstrappedAt)
	})
	return position, err
}

const seedStatement = `INSERT INTO projection.membership
    (tenant_id, principal_id, membership_id, membership_status, membership_version,
     applied_mark, tenant_security_version, applied_at, event_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (tenant_id, principal_id) DO UPDATE
   SET membership_id           = excluded.membership_id,
       membership_status       = excluded.membership_status,
       membership_version      = excluded.membership_version,
       applied_mark            = excluded.applied_mark,
       tenant_security_version = excluded.tenant_security_version,
       applied_at              = excluded.applied_at,
       event_id                = excluded.event_id
 WHERE excluded.applied_mark > membership.applied_mark`

// Recording the snapshot mark inserts when absent, because a consumer's watermark row appears when
// it first applies something or first bootstraps, whichever happens first — and a consumer may
// legitimately bootstrap before any event has arrived.
const recordSnapshot = `INSERT INTO projection.watermark
    (consumer, snapshot_mark, applied_mark, bootstrapped_at, updated_at)
VALUES ($1, $2, 0, $3, $3)
ON CONFLICT (consumer) DO UPDATE
   SET snapshot_mark   = excluded.snapshot_mark,
       bootstrapped_at = excluded.bootstrapped_at,
       updated_at      = excluded.updated_at`

// Seeded is one row of a snapshot page.
type Seeded struct {
	MembershipID          id.UUID
	TenantID              id.UUID
	PrincipalID           id.UUID
	Status                Status
	Version               int64
	TenantSecurityVersion int64
}

// Seed applies one snapshot page at the snapshot's mark, and records the mark when the page is the
// last one.
//
// The mark rather than each row's own position, because a snapshot is a statement about one instant:
// every row in it was true at mark M, and an event after M supersedes it. Seeding rows at position
// zero would make every subsequent event look newer than the snapshot including events the snapshot
// already contains — harmless for status, and wrong for the ordering rule the moment a membership is
// replaced.
func (p *Projector) Seed(ctx context.Context, rows []Seeded, mark int64, final bool) error {
	if mark <= 0 {
		return fmt.Errorf("%w: a snapshot mark is required", ErrMalformed)
	}

	return p.pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		at := p.now().UTC()
		for _, row := range rows {
			if row.MembershipID.IsNil() || row.TenantID.IsNil() || row.PrincipalID.IsNil() {
				return fmt.Errorf("%w: a snapshot row is missing an identifier", ErrMalformed)
			}
			if _, err := tx.Exec(ctx, seedStatement,
				row.TenantID.String(), row.PrincipalID.String(), row.MembershipID.String(),
				string(row.Status), row.Version, mark, row.TenantSecurityVersion, at,
				row.MembershipID.String()); err != nil {
				return fmt.Errorf("projection: seeding %s: %w", row.MembershipID, err)
			}
		}

		if final {
			if _, err := tx.Exec(ctx, recordSnapshot, p.consumer, mark, at); err != nil {
				return fmt.Errorf("projection: recording the snapshot mark: %w", err)
			}
		}
		return nil
	})
}

const ageStatement = `SELECT snapshot_mark IS NOT NULL, now() - updated_at
  FROM projection.watermark WHERE consumer = $1`

// Age reports how long since this consumer applied anything, and whether it has bootstrapped at all.
//
// It is a lag HINT, not proof of convergence, and the principal review is right to refuse it as a
// security invariant: it answers "when did the last event land" and not "have all events landed".
// One event delivered at 10:05 makes it look fresh while an event from 10:00 is still in flight.
//
// It is kept because the LOW_RISK window needs some measure and this is the only one available on
// this side. The measure that would be sound has to come from the producer, which is the only side
// that knows which outbox rows remain unpublished -- a sequence gap here is indistinguishable from a
// rolled-back transaction, by the producer's own design.
//
// ErrNotBootstrapped is a different matter and IS sound: a consumer with no snapshot mark holds no
// positive authority for anything, whatever its age says.
func (p *Projector) Age(ctx context.Context) (time.Duration, error) {
	var (
		bootstrapped bool
		age          time.Duration
	)
	err := p.pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, ageStatement, p.consumer)
		if err != nil {
			return fmt.Errorf("projection: reading freshness: %w", err)
		}
		defer rows.Close()
		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return fmt.Errorf("projection: reading freshness: %w", err)
			}
			// No row: this consumer has never applied anything, so it certainly never bootstrapped.
			bootstrapped = false
			return nil
		}
		return rows.Scan(&bootstrapped, &age)
	})
	if err != nil {
		return 0, err
	}
	if !bootstrapped {
		return age, ErrNotBootstrapped
	}
	if age < 0 {
		age = 0
	}
	return age, nil
}
