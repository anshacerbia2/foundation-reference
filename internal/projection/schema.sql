-- The consumer's own projection of Membership authority.
--
-- Not authoritative, and it says so in its name: this is a replica of somebody else's decision, kept
-- only so an enforcement check can be answered without a network call. Its recovery path is
-- rebuild-from-snapshot rather than repair, which is why rebuild.sql exists and why this file never
-- drops anything: a normal migration run must not delete a projection.
--
-- No row-level security. RLS in organization-control protects authoritative tenant data; this table
-- holds one status and two versions per membership, replicated from events this consumer was sent.
-- Adding RLS would imply a tenancy guarantee this deployable is not the authority for.

CREATE SCHEMA IF NOT EXISTS projection;

CREATE TABLE IF NOT EXISTS projection.membership (
    -- Keyed by the membership, one row each.
    --
    -- Keyed by (tenant_id, principal_id) first, which was wrong: the authority permits several
    -- active memberships for one principal in one tenant. Its own constraint says so --
    --
    --     unique (principal_id, tenant_id, COALESCE(workspace_id, tenant_id)) where status='active'
    --
    -- so a principal may hold one tenant-wide membership and one per workspace. Collapsing them into
    -- a single row meant the second event overwrote the first, and revoking either would report the
    -- principal as revoked across the tenant while they still held the other. A false deny in
    -- production, not a modelling preference.
    membership_id uuid PRIMARY KEY,

    tenant_id    uuid NOT NULL,
    principal_id uuid NOT NULL,

    -- The workspace this membership is scoped to, NULL for a tenant-wide one. Carried so the two
    -- kinds are distinguishable in the projection the way they are in the authority.
    workspace_id uuid,

    -- Positive state, not a deny-list. A consumer holding only revocations cannot tell "this
    -- principal holds an active membership" from "this principal was never a member" -- both are an
    -- absent row -- so absence had to mean "allow", and the answer to an enforcement question was
    -- the absence of bad news. Projecting status makes absence mean no positive authority.
    membership_status text NOT NULL
        CHECK (membership_status IN ('active', 'suspended', 'revoked')),

    -- membership_version is monotonic per membership, and one row is one membership, so it orders
    -- this row's events completely. Nothing here compares versions across memberships -- which is
    -- what keying by membership removed rather than solved: with one row per pair, an older version
    -- for a replacement membership had to be ordered somehow, and the only candidate was the
    -- producer's stream position. That position is ALLOCATION order, not commit order, because the
    -- outbox takes its sequence before the transaction commits.
    membership_version bigint NOT NULL CHECK (membership_version > 0),

    -- The producer's stream position for the event that produced this state. Kept for lag and triage,
    -- and no longer load-bearing for ordering.
    applied_mark bigint NOT NULL CHECK (applied_mark > 0),

    -- Carried so a caller can compare a token it holds against this answer. Not enforced yet, and
    -- named here rather than added silently later.
    tenant_security_version bigint NOT NULL DEFAULT 0,

    -- When this consumer applied it, not when the authority decided it. Keeping both would invite
    -- reading the producer's clock as if it were comparable to this one.
    applied_at timestamptz NOT NULL,

    -- The delivery that produced the current state, for triage: it joins this row to
    -- platform.processed_event and to the producer's outbox row.
    event_id uuid NOT NULL
);

-- Enforcement asks "does this principal hold an active membership in this tenant", so that is the
-- read this index serves. Partial on active, because a principal with a thousand revoked memberships
-- should cost the same to check as one with none.
CREATE INDEX IF NOT EXISTS membership_active_context_idx
    ON projection.membership (tenant_id, principal_id)
    WHERE membership_status = 'active';

-- The full-context index for the refusal path: telling "never seen" apart from "seen and withdrawn"
-- needs the rows that the partial index above excludes.
CREATE INDEX IF NOT EXISTS membership_context_idx
    ON projection.membership (tenant_id, principal_id);

-- Freshness and lag are read on every projection-backed enforcement check.
CREATE INDEX IF NOT EXISTS membership_applied_mark_idx
    ON projection.membership (applied_mark DESC);

-- The consumer's own position, one row.
--
-- Separate from the membership table because it must survive a membership table with no rows: a
-- consumer that has bootstrapped from an empty estate is in a completely different state from one
-- that never bootstrapped, and only this table can tell them apart.
CREATE TABLE IF NOT EXISTS projection.watermark (
    -- Keyed by consumer, not a single row.
    --
    -- The position belongs to the logical consumer: platform.processed_event deduplicates per
    -- (event_id, consumer), so two consumers sharing this database each apply every event and each
    -- have their own position. A single row made one consumer's bootstrap look like everybody's --
    -- which surfaced as a test seeing itself bootstrapped because another test had seeded, and would
    -- surface in production as a replica serving from authority it never took a snapshot for.
    consumer text PRIMARY KEY,

    -- The mark the snapshot was taken at. NULL until a snapshot completes, and a NULL here means
    -- this consumer holds no positive authority for anything -- every projection-backed enforcement
    -- check must refuse.
    snapshot_mark bigint,

    -- The highest stream position applied since the snapshot. It is a lag metric and NOT a proof of
    -- convergence: the outbox allocates sequence values before commit, so gaps below it are
    -- expected and a contiguous frontier cannot be derived from it.
    applied_mark bigint NOT NULL DEFAULT 0,

    bootstrapped_at timestamptz,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- No seed row: a consumer's row appears when it bootstraps. An absent row is the honest
-- representation of "this consumer has taken no snapshot", and seeding one would make the absence
-- indistinguishable from a snapshot at position zero.
