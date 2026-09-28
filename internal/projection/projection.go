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
// # One row per membership, and the question asked at the read
//
// The authority permits several active memberships for one principal in one tenant -- one tenant-wide
// and one per workspace, by its own unique constraint. Keying this table by (tenant_id, principal_id)
// collapsed them, so the second event overwrote the first and revoking either reported the principal
// as revoked across the tenant while they still held the other.
//
// One row per membership instead, ordered by that membership's own version, which the authority
// increments under a row lock. Nothing compares versions across memberships, which removes rather
// than solves the ordering hazard: the previous shape needed the producer's stream position as a
// tiebreak, and that position is ALLOCATION order -- the outbox takes its sequence before the
// transaction commits, so two transitions can commit in the opposite order to their numbers.
//
// The cross-membership question moves to the read, where it belongs: does an active membership exist
// for this pair. That is answerable from whatever rows have arrived, in any order.
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

// The four Tenant event types that change whether a Tenant's contexts are valid. Each carries the
// Tenant's complete status and its tenant_security_version (TDD-organization-control-002 §Published
// Events), so the version, not delivery order, decides which state is newer.
//
// Offboarding publishes tenant.security.suspended as well, carrying tenant_status "offboarding":
// one event type for both, because the consequence is the same and the status says which.
const (
	TenantActivated event.Type = "com.scnehaux.organization.tenant.lifecycle.activated"
	TenantSuspended event.Type = "com.scnehaux.organization.tenant.security.suspended"
	TenantRestored  event.Type = "com.scnehaux.organization.tenant.security.restored"
	TenantRetired   event.Type = "com.scnehaux.organization.tenant.lifecycle.retired"
)

var tenantTypes = map[event.Type]bool{
	TenantActivated: true,
	TenantSuspended: true,
	TenantRestored:  true,
	TenantRetired:   true,
}

// acknowledged are the producer's event types this consumer receives and does not act on.
//
// The dispatcher delivers every event the producer publishes, and before this list existed every one
// of these was refused as an unknown type -- poison, dead-lettered, and never closable, because a
// replay is refused again and none of them is a Membership event. So every Workspace change and every
// invitation left an incident that alerted forever.
//
// Listed by name rather than by a rule such as "anything not security-class". A type added later is
// still refused until someone decides here whether this consumer needs it, which is the property
// the refusal existed for: a consumer that silently skips a type it does not recognise reports success
// for work it never did. projection.repair.reconciled is absent because it is applied, not
// acknowledged: see repair.go.
var acknowledged = map[event.Type]bool{
	"com.scnehaux.organization.workspace.lifecycle.created":     true,
	"com.scnehaux.organization.workspace.lifecycle.archived":    true,
	"com.scnehaux.organization.workspace.lifecycle.restored":    true,
	"com.scnehaux.organization.workspace.lifecycle.retired":     true,
	"com.scnehaux.organization.organization.registry.created":   true,
	"com.scnehaux.organization.organization.registry.suspended": true,
	"com.scnehaux.organization.organization.registry.restored":  true,
	"com.scnehaux.organization.organization.registry.retired":   true,
	"com.scnehaux.organization.membership.invitation.requested": true,
	"com.scnehaux.organization.membership.invitation.accepted":  true,
	"com.scnehaux.organization.membership.invitation.revoked":   true,
	"com.scnehaux.organization.membership.invitation.expired":   true,
	"com.scnehaux.organization.tenant.offboarding.started":      true,
	"com.scnehaux.organization.tenant.offboarding.frozen":       true,
	"com.scnehaux.organization.tenant.offboarding.released":     true,
	"com.scnehaux.organization.tenant.lifecycle.requested":      true,
}

var (
	ErrNoPool          = errors.New("projection: a pool is required")
	ErrNoConsumer      = errors.New("projection: a consumer name is required")
	ErrUnknownType     = errors.New("projection: event type is not one this consumer applies")
	ErrMalformed       = errors.New("projection: payload does not carry the members this consumer needs")
	ErrNotProjected    = errors.New("projection: no membership is projected for this tenant and principal")
	ErrNotBootstrapped = errors.New("projection: this consumer has taken no snapshot, so it holds no positive authority")

	// ErrTenantInactive means the Tenant is projected and is not active: suspended, offboarding or
	// retired. Every member is refused, as the authority's own check refuses them.
	ErrTenantInactive = errors.New("projection: the tenant is not active")

	// ErrTenantNotProjected means an active membership exists and its Tenant's state has not
	// arrived. Refused rather than assumed active: absence here means no positive authority, as it
	// does for a membership.
	ErrTenantNotProjected = errors.New("projection: no tenant state is projected for this tenant")
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

	// WorkspaceID is null for a tenant-wide membership. Read because it is what makes several active
	// memberships legal for one pair, so a projection that dropped it could not explain its own rows.
	WorkspaceID *id.UUID `json:"workspace_id"`

	// Status as the producer sees it. Read but not trusted over the event type: a granted event
	// carrying "revoked" is a contradiction, and the type is the thing the dispatcher routed on.
	Status string `json:"membership_status"`

	TenantSecurityVersion int64 `json:"tenant_security_version"`
}

// workspace renders the optional workspace for the database, where nil must be NULL rather than the
// zero UUID: the authority's own constraint folds NULL into the tenant-wide case, and a zero UUID
// would be a workspace that does not exist.
func (p Payload) workspace() any {
	if p.WorkspaceID == nil || p.WorkspaceID.IsNil() {
		return nil
	}
	return p.WorkspaceID.String()
}

// Record is what an enforcement decision reads.
type Record struct {
	MembershipID          id.UUID
	TenantID              id.UUID
	PrincipalID           id.UUID
	WorkspaceID           *id.UUID
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

	// Acknowledged means the event is one this consumer receives and does not act on. Nothing was
	// applied, so no application receipt is due.
	Acknowledged bool

	Record Record
}

// TenantPayload is the subset of a Tenant event this consumer reads.
type TenantPayload struct {
	TenantID              id.UUID `json:"tenant_id"`
	TenantStatus          string  `json:"tenant_status"`
	TenantSecurityVersion int64   `json:"tenant_security_version"`
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

// The ordering rule, in SQL: one row per membership, ordered by that membership's own version.
//
// This is what keying by membership removed rather than solved. With one row per (tenant, principal),
// a grant for a replacement membership carried a lower version than the revocation it replaced, and
// the only available tiebreak was the producer's stream position -- which is ALLOCATION order, not
// commit order, because the outbox takes its sequence before the transaction commits. Two transitions
// could therefore commit in the opposite order to their numbers, and the projection would settle on
// the wrong one.
//
// Keyed by membership, no comparison crosses memberships at all: each row advances only on its own
// version, which the authority increments under a row lock. The cross-membership question moves to
// the read, where it belongs -- "does an active membership exist for this pair" -- and is answered
// from whatever rows have arrived, in any order.
const upsertStatement = `INSERT INTO projection.membership
    (membership_id, tenant_id, principal_id, workspace_id, membership_status, membership_version,
     applied_mark, tenant_security_version, applied_at, event_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (membership_id) DO UPDATE
   SET membership_status       = excluded.membership_status,
       membership_version      = excluded.membership_version,
       applied_mark            = excluded.applied_mark,
       tenant_security_version = excluded.tenant_security_version,
       applied_at              = excluded.applied_at,
       event_id                = excluded.event_id
 WHERE excluded.membership_version > membership.membership_version`

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
	switch {
	case tenantTypes[envelope.Type]:
		return p.applyTenant(ctx, envelope)
	case acknowledged[envelope.Type]:
		return p.acknowledge(ctx, envelope)
	case envelope.Type == RepairReconciled:
		return p.applyRepair(ctx, envelope)
	}

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
			payload.MembershipID.String(), payload.TenantID.String(), payload.PrincipalID.String(),
			payload.workspace(), string(status), payload.Version, envelope.StreamPosition,
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

// The ordering rule for a Tenant: its security version, which the authority increments under a row
// lock on every transition that changes whether the Tenant's contexts are valid. An event carrying a
// version no higher than the one held is older, or a duplicate, and changes nothing.
const upsertTenantStatement = `INSERT INTO projection.tenant
    (tenant_id, tenant_status, tenant_security_version, applied_mark, applied_at, event_id)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (tenant_id) DO UPDATE
   SET tenant_status           = excluded.tenant_status,
       tenant_security_version = excluded.tenant_security_version,
       applied_mark            = excluded.applied_mark,
       applied_at              = excluded.applied_at,
       event_id                = excluded.event_id
 WHERE excluded.tenant_security_version > tenant.tenant_security_version`

// applyTenant projects one Tenant event, under the same inbox guard and in the same transaction as
// the watermark, as a Membership event is.
func (p *Projector) applyTenant(ctx context.Context, envelope event.Envelope) (Outcome, error) {
	if envelope.StreamPosition <= 0 {
		return Outcome{}, fmt.Errorf("%w: the envelope carries no stream position", ErrMalformed)
	}
	var payload TenantPayload
	if err := json.Unmarshal(envelope.Data, &payload); err != nil {
		return Outcome{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if payload.TenantID.IsNil() || payload.TenantStatus == "" || payload.TenantSecurityVersion <= 0 {
		return Outcome{}, fmt.Errorf("%w: tenant_id, tenant_status and a positive tenant_security_version are required",
			ErrMalformed)
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
		tag, err := tx.Exec(ctx, upsertTenantStatement, payload.TenantID.String(), payload.TenantStatus,
			payload.TenantSecurityVersion, envelope.StreamPosition, appliedAt, envelope.ID.String())
		if err != nil {
			return fmt.Errorf("projection: applying %s: %w", envelope.ID, err)
		}
		if _, err := tx.Exec(ctx, advanceWatermark, p.consumer, envelope.StreamPosition, appliedAt); err != nil {
			return fmt.Errorf("projection: advancing the watermark: %w", err)
		}
		if tag.RowsAffected() == 0 {
			outcome.Superseded = true
			return nil
		}
		outcome.Applied = true
		outcome.Record = Record{TenantID: payload.TenantID, TenantSecurityVersion: payload.TenantSecurityVersion,
			AppliedMark: envelope.StreamPosition, AppliedAt: appliedAt}
		return nil
	})
	if err != nil {
		return Outcome{}, err
	}
	return outcome, nil
}

// acknowledge records that an event this consumer does not act on was seen: the watermark advances,
// because the delivery happened, and nothing else changes.
func (p *Projector) acknowledge(ctx context.Context, envelope event.Envelope) (Outcome, error) {
	if envelope.StreamPosition <= 0 {
		return Outcome{}, fmt.Errorf("%w: the envelope carries no stream position", ErrMalformed)
	}
	err := p.pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, advanceWatermark, p.consumer, envelope.StreamPosition, p.now().UTC())
		return err
	})
	if err != nil {
		return Outcome{}, fmt.Errorf("projection: acknowledging %s: %w", envelope.ID, err)
	}
	return Outcome{Acknowledged: true}, nil
}

// ErrWithdrawn means rows exist for this pair and none of them is active. Distinct from
// ErrNotProjected on purpose: both refuse, and only one of them means the consumer has actually seen
// this principal. An operator reading a refusal needs to know which.
var ErrWithdrawn = errors.New("projection: this principal holds no active membership in this tenant")

// Enforcement asks one question -- does an active membership exist for this pair -- and it is asked as
// EXISTS rather than as "read the row and check its status", because there may be several rows and
// only one of them needs to be active.
//
// The newest active one is returned when several are: the version and mark are reported to the caller,
// and reporting the oldest would understate how current the answer is.
const activeStatement = `SELECT membership_id, workspace_id, membership_version,
       tenant_security_version, applied_mark, applied_at
  FROM projection.membership
 WHERE tenant_id = $1 AND principal_id = $2 AND membership_status = 'active'
 ORDER BY applied_mark DESC
 LIMIT 1`

const anyStatement = `SELECT count(*) FROM projection.membership
 WHERE tenant_id = $1 AND principal_id = $2`

// One row always, NULL when the Tenant has not been projected, so absence is a value to test rather
// than an error to recognise.
const tenantStatement = `SELECT t.tenant_status
  FROM (SELECT 1) one
  LEFT JOIN projection.tenant t ON t.tenant_id = $1`

// Lookup answers whether this principal holds an active membership in this tenant.
//
// The Tenant is read first, as the authority's own check reads it: a member of a Tenant that is not
// active holds nothing, whatever their Membership says. Five outcomes, and the caller needs them apart:
//
//	the tenant is projected and not active     -> ErrTenantInactive
//	an active membership, tenant active        -> the record, nil
//	an active membership, tenant not projected -> ErrTenantNotProjected
//	rows but none active                       -> ErrWithdrawn
//	no rows at all                             -> ErrNotProjected
func (p *Projector) Lookup(ctx context.Context, tenantID, principalID id.UUID) (Record, error) {
	record := Record{TenantID: tenantID, PrincipalID: principalID, Status: Active}

	err := p.pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var tenantStatus *string
		if err := tx.QueryRow(ctx, tenantStatement, tenantID.String()).Scan(&tenantStatus); err != nil {
			return fmt.Errorf("projection: reading tenant %s: %w", tenantID, err)
		}
		if tenantStatus != nil && *tenantStatus != "active" {
			return fmt.Errorf("%w: %s is %s", ErrTenantInactive, tenantID, *tenantStatus)
		}

		rows, err := tx.Query(ctx, activeStatement, tenantID.String(), principalID.String())
		if err != nil {
			return fmt.Errorf("projection: reading (%s, %s): %w", tenantID, principalID, err)
		}
		defer rows.Close()

		if rows.Next() {
			var membership string
			var workspace *string
			if err := rows.Scan(&membership, &workspace, &record.Version,
				&record.TenantSecurityVersion, &record.AppliedMark, &record.AppliedAt); err != nil {
				return fmt.Errorf("projection: scanning (%s, %s): %w", tenantID, principalID, err)
			}
			parsed, err := id.Parse(membership)
			if err != nil {
				return fmt.Errorf("projection: stored membership_id is not a UUID: %w", err)
			}
			record.MembershipID = parsed
			if workspace != nil {
				scoped, err := id.Parse(*workspace)
				if err != nil {
					return fmt.Errorf("projection: stored workspace_id is not a UUID: %w", err)
				}
				record.WorkspaceID = &scoped
			}
			if tenantStatus == nil {
				return fmt.Errorf("%w: %s", ErrTenantNotProjected, tenantID)
			}
			return nil
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("projection: reading (%s, %s): %w", tenantID, principalID, err)
		}
		rows.Close()

		// No active membership. Whether this pair is known at all decides which refusal it is.
		var seen int
		if err := tx.QueryRow(ctx, anyStatement, tenantID.String(), principalID.String()).Scan(&seen); err != nil {
			return fmt.Errorf("projection: counting (%s, %s): %w", tenantID, principalID, err)
		}
		if seen > 0 {
			return ErrWithdrawn
		}
		return ErrNotProjected
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
    (membership_id, tenant_id, principal_id, workspace_id, membership_status, membership_version,
     applied_mark, tenant_security_version, applied_at, event_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (membership_id) DO UPDATE
   SET membership_status       = excluded.membership_status,
       membership_version      = excluded.membership_version,
       applied_mark            = excluded.applied_mark,
       tenant_security_version = excluded.tenant_security_version,
       applied_at              = excluded.applied_at,
       event_id                = excluded.event_id
 WHERE excluded.membership_version > membership.membership_version`

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
	WorkspaceID           *id.UUID
	Status                Status
	Version               int64
	TenantSecurityVersion int64

	// TenantStatus is the Tenant's status at the snapshot's mark, seeded into projection.tenant under
	// the same ordering rule as a Tenant event. The membership keeps its own status.
	TenantStatus string
}

func (s Seeded) workspace() any {
	if s.WorkspaceID == nil || s.WorkspaceID.IsNil() {
		return nil
	}
	return s.WorkspaceID.String()
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
				row.MembershipID.String(), row.TenantID.String(), row.PrincipalID.String(),
				row.workspace(), string(row.Status), row.Version, mark,
				row.TenantSecurityVersion, at, row.MembershipID.String()); err != nil {
				return fmt.Errorf("projection: seeding %s: %w", row.MembershipID, err)
			}
			// Every row carries its Tenant's state, so a Tenant appears once per member; the ordering
			// rule makes the repeats no-ops, and an event newer than the snapshot is never overwritten.
			if row.TenantStatus == "" || row.TenantSecurityVersion <= 0 {
				return fmt.Errorf("%w: a snapshot row for %s carries no tenant state", ErrMalformed, row.MembershipID)
			}
			if _, err := tx.Exec(ctx, upsertTenantStatement, row.TenantID.String(), row.TenantStatus,
				row.TenantSecurityVersion, mark, at, nil); err != nil {
				return fmt.Errorf("projection: seeding tenant %s: %w", row.TenantID, err)
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

const byMembershipStatement = `SELECT tenant_id, principal_id, workspace_id, membership_status,
       membership_version, tenant_security_version, applied_mark, applied_at
  FROM projection.membership WHERE membership_id = $1`

// LookupMembership reads one membership by identity, whatever its status.
//
// Not the enforcement read: enforcement asks whether an active membership exists for a pair, and a
// caller that fetched a membership and inspected its status would be answering a narrower question
// than the one it has. This exists for triage -- joining a refusal to the row and the event that
// produced it -- and for tests that assert what a delivery did to a specific membership.
func (p *Projector) LookupMembership(ctx context.Context, membershipID id.UUID) (Record, error) {
	record := Record{MembershipID: membershipID}

	err := p.pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, byMembershipStatement, membershipID.String())
		if err != nil {
			return fmt.Errorf("projection: reading %s: %w", membershipID, err)
		}
		defer rows.Close()

		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return fmt.Errorf("projection: reading %s: %w", membershipID, err)
			}
			return ErrNotProjected
		}

		var tenant, principal, status string
		var workspace *string
		if err := rows.Scan(&tenant, &principal, &workspace, &status, &record.Version,
			&record.TenantSecurityVersion, &record.AppliedMark, &record.AppliedAt); err != nil {
			return fmt.Errorf("projection: scanning %s: %w", membershipID, err)
		}

		parsedTenant, err := id.Parse(tenant)
		if err != nil {
			return fmt.Errorf("projection: stored tenant_id is not a UUID: %w", err)
		}
		parsedPrincipal, err := id.Parse(principal)
		if err != nil {
			return fmt.Errorf("projection: stored principal_id is not a UUID: %w", err)
		}
		record.TenantID, record.PrincipalID, record.Status = parsedTenant, parsedPrincipal, Status(status)
		if workspace != nil {
			scoped, err := id.Parse(*workspace)
			if err != nil {
				return fmt.Errorf("projection: stored workspace_id is not a UUID: %w", err)
			}
			record.WorkspaceID = &scoped
		}
		return nil
	})
	if err != nil {
		return Record{}, err
	}
	return record, nil
}
