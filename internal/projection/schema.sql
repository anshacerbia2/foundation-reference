-- The consumer's own projection. It is not authoritative and says so in its name: this is a
-- replica of somebody else's decision, kept only so an enforcement check can be answered
-- without a network call.
--
-- No row-level security here, and that is deliberate rather than an omission. RLS in
-- organization-control protects authoritative tenant data; this table holds one boolean and
-- a version per membership, replicated from events this consumer was sent. Adding RLS would
-- imply a tenancy guarantee this deployable is not the authority for.

CREATE SCHEMA IF NOT EXISTS projection;

CREATE TABLE IF NOT EXISTS projection.membership (
    membership_id uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL,
    principal_id  uuid NOT NULL,

    -- Only revocations are projected today, so this is always true once a row exists. It is
    -- a column rather than implied by the row's presence because the next event type this
    -- consumer learns to apply will be a reinstatement, and a row's presence cannot carry
    -- two meanings.
    revoked boolean NOT NULL,

    -- The monotonicity guard compares against this. An event carrying a lower version is
    -- discarded by the WHERE clause on the upsert, which is what makes out-of-order
    -- delivery harmless and broker ordering a performance concern rather than a
    -- correctness one.
    version bigint NOT NULL CHECK (version > 0),

    -- When this consumer applied it, not when the authority decided it. The difference is
    -- the propagation delay Proof A exists to measure, and keeping both timestamps would
    -- invite reading the producer's clock as if it were comparable to this one.
    applied_at timestamptz NOT NULL,

    -- The delivery that produced the current state, for triage: it joins this row to
    -- platform.processed_event and to the producer's outbox row.
    event_id uuid NOT NULL
);

-- Freshness is read on every projection-backed enforcement check, so it must not be a
-- sequential scan once this table is large.
CREATE INDEX IF NOT EXISTS membership_applied_at_idx
    ON projection.membership (applied_at DESC);
