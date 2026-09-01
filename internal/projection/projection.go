// Package projection applies membership events and answers the one question an enforcing
// consumer has to answer: is this membership still valid, and how stale is that answer.
//
// Two properties carry the whole design, and both are asserted rather than assumed.
//
// # Duplicate delivery cannot apply an effect twice
//
// inbox.Guard registers the event inside the same transaction that applies it. Registering
// in a separate transaction would leave a window where a crash marks an event processed
// whose effect rolled back, and the redelivery — the very mechanism that would have fixed
// it — is then discarded as a duplicate.
//
// # Out-of-order delivery is harmless
//
// The version is monotonic and the effect is idempotent, so an older event arriving after a
// newer one is discarded by the WHERE clause rather than by broker ordering. That is what
// lets the broker be chosen on operational grounds instead of on per-key ordering
// guarantees, and TestOutOfOrderDeliveryIsHarmless is the assertion that it is true.
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

// MembershipRevoked is the event type this consumer enforces on.
const MembershipRevoked event.Type = "com.scnehaux.organization.membership.security.revoked"

var (
	ErrNoPool         = errors.New("projection: a pool is required")
	ErrNoConsumer     = errors.New("projection: a consumer name is required")
	ErrUnknownType    = errors.New("projection: event type is not one this consumer applies")
	ErrMalformed      = errors.New("projection: payload does not carry the members this consumer needs")
	ErrNotProjected   = errors.New("projection: this membership has never been seen")
	ErrProjectionCold = errors.New("projection: nothing has been applied, so freshness is unknown")
)

// Payload is the subset of the event this consumer reads. It is deliberately narrow: a
// consumer that decodes the producer's whole record acquires a dependency on every field
// the producer later adds.
type Payload struct {
	MembershipID id.UUID `json:"membership_id"`
	TenantID     id.UUID `json:"tenant_id"`
	PrincipalID  id.UUID `json:"principal_id"`

	// membership_version, not "version". The producer's name, read from a real event rather than
	// assumed: the first end-to-end run refused every delivery with "membership_id and a positive
	// version are required" because this field was called version here and nothing carried it.
	//
	// The consumer's tests had passed throughout, because they built payloads from this same struct
	// -- a fixture and a producer that agree with each other and with nobody else.
	Version int64 `json:"membership_version"`

	// TenantSecurityVersion travels with the event and is not projected yet. Named here so the
	// contract this consumer reads is visible in one place; a field added silently later would be
	// indistinguishable from one that was always ignored.
	TenantSecurityVersion int64 `json:"tenant_security_version"`
}

// Record is what an enforcement decision reads.
type Record struct {
	MembershipID id.UUID
	TenantID     id.UUID
	PrincipalID  id.UUID
	Revoked      bool
	Version      int64
	AppliedAt    time.Time
}

// Outcome reports what applying one delivery did, so the caller can distinguish the three
// cases that look identical from the outside: applied, already seen, and superseded.
type Outcome struct {
	Applied    bool
	Duplicate  bool
	Superseded bool
	Record     Record
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

// The WHERE clause on the DO UPDATE is the monotonicity guard, and it is the whole reason
// broker ordering is not a correctness requirement here.
//
// Exec rather than RETURNING: a refused update returns no row, and distinguishing "no row"
// from a scan failure would mean reaching for the driver's sentinel. RowsAffected says the
// same thing without the coupling — 1 applied, 0 superseded.
const upsertStatement = `INSERT INTO projection.membership
    (membership_id, tenant_id, principal_id, revoked, version, applied_at, event_id)
VALUES ($1, $2, $3, TRUE, $4, $5, $6)
ON CONFLICT (membership_id) DO UPDATE
   SET revoked      = TRUE,
       tenant_id    = excluded.tenant_id,
       principal_id = excluded.principal_id,
       version      = excluded.version,
       applied_at   = excluded.applied_at,
       event_id     = excluded.event_id
 WHERE excluded.version > membership.version`

// Apply projects one delivery. It is safe to call with the same envelope any number of
// times, in any order relative to other envelopes for the same membership.
func (p *Projector) Apply(ctx context.Context, envelope event.Envelope) (Outcome, error) {
	if envelope.Type != MembershipRevoked {
		return Outcome{}, fmt.Errorf("%w: %s", ErrUnknownType, envelope.Type)
	}

	var payload Payload
	if err := json.Unmarshal(envelope.Data, &payload); err != nil {
		return Outcome{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if payload.MembershipID.IsNil() || payload.Version <= 0 {
		return Outcome{}, fmt.Errorf("%w: membership_id and a positive version are required", ErrMalformed)
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
			payload.Version, appliedAt, envelope.ID.String())
		if err != nil {
			return fmt.Errorf("projection: applying %s: %w", envelope.ID, err)
		}

		if tag.RowsAffected() == 0 {
			// The monotonicity guard refused the update: a newer version is already
			// applied. The delivery is accounted for and nothing regressed. This is the
			// out-of-order case, and it is a success rather than an error.
			outcome.Superseded = true
			return nil
		}

		outcome.Applied = true
		outcome.Record = Record{
			MembershipID: payload.MembershipID,
			TenantID:     payload.TenantID,
			PrincipalID:  payload.PrincipalID,
			Revoked:      true,
			Version:      payload.Version,
			AppliedAt:    appliedAt,
		}
		return nil
	})
	if err != nil {
		return Outcome{}, err
	}
	return outcome, nil
}

const lookupStatement = `SELECT membership_id, tenant_id, principal_id, revoked, version, applied_at
  FROM projection.membership WHERE tenant_id = $1 AND principal_id = $2`

// Lookup answers from the projection alone, keyed by the pair enforcement actually asks about.
//
// Not by membership identifier: `may this principal act in this tenant` is the question a
// product has, and the membership is the authority's answer to it rather than the caller's
// input. A caller that had to supply a membership_id would have to learn it from somewhere,
// and the only place available is this replica -- so the check would depend on the replica
// twice, including for the classes that must not depend on it at all.
//
// Callers that must not depend on a replica ask the authority instead; see internal/httpapi.
func (p *Projector) Lookup(ctx context.Context, tenantID, principalID id.UUID) (Record, error) {
	var record Record
	err := p.pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		// Query and Next rather than QueryRow: absence is an expected answer here, and
		// telling it apart from a scan failure through QueryRow means comparing against the
		// driver's own sentinel. "The membership is unknown to this consumer" and "the read
		// broke" have to reach the caller as different things — the first is fail-open
		// eligible, the second never is.
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

		var membership, tenant, principal string
		if err := rows.Scan(&membership, &tenant, &principal, &record.Revoked, &record.Version, &record.AppliedAt); err != nil {
			return fmt.Errorf("projection: scanning (%s, %s): %w", tenantID, principalID, err)
		}
		var parseErr error
		if record.MembershipID, parseErr = id.Parse(membership); parseErr != nil {
			return fmt.Errorf("projection: stored membership_id is not a UUID: %w", parseErr)
		}
		if record.TenantID, parseErr = id.Parse(tenant); parseErr != nil {
			return fmt.Errorf("projection: stored tenant_id is not a UUID: %w", parseErr)
		}
		if record.PrincipalID, parseErr = id.Parse(principal); parseErr != nil {
			return fmt.Errorf("projection: stored principal_id is not a UUID: %w", parseErr)
		}
		return nil
	})
	if err != nil {
		return Record{}, err
	}
	return record, nil
}

const freshnessStatement = `SELECT max(applied_at) FROM projection.membership`

// Age reports how long ago this projection last applied anything.
//
// It is the input to every fail-open decision, and it is deliberately a property of the
// projection rather than of the process: a replica that has been up for an hour without
// receiving an event is exactly as stale as one that just started.
func (p *Projector) Age(ctx context.Context) (time.Duration, error) {
	var age time.Duration
	err := p.pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var appliedAt *time.Time
		if err := tx.QueryRow(ctx, freshnessStatement).Scan(&appliedAt); err != nil {
			return fmt.Errorf("projection: reading freshness: %w", err)
		}
		if appliedAt == nil {
			return ErrProjectionCold
		}
		age = p.now().UTC().Sub(appliedAt.UTC())
		if age < 0 {
			age = 0
		}
		return nil
	})
	return age, err
}
