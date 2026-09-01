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
    -- Keyed by the pair enforcement asks about: "may this principal act in this tenant". The
    -- membership is the authority's answer to that question rather than the caller's input.
    tenant_id    uuid NOT NULL,
    principal_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, principal_id),

    -- Which membership the current state belongs to. Load-bearing rather than informational: see
    -- the ordering rule below.
    membership_id uuid NOT NULL,

    -- Positive state, not a deny-list. A consumer holding only revocations cannot tell "this
    -- principal holds an active membership" from "this principal was never a member" -- both are an
    -- absent row -- so absence had to mean "allow", and the answer to an enforcement question was
    -- the absence of bad news. Projecting status makes absence mean no positive authority.
    membership_status text NOT NULL
        CHECK (membership_status IN ('active', 'suspended', 'revoked')),

    -- membership_version is monotonic PER MEMBERSHIP, and only per membership.
    --
    -- A principal may hold membership A, have it revoked at version 5, and be granted membership B
    -- at version 1 in the same tenant. Comparing 1 against 5 would discard the grant and leave the
    -- revocation standing forever, so the version alone cannot order two rows that name different
    -- memberships.
    membership_version bigint NOT NULL CHECK (membership_version > 0),

    -- applied_mark is the producer's stream position for the event that produced this state, and it
    -- is what orders events ACROSS memberships: the outbox sequence is the authority's own commit
    -- order, which is the only total order both sides agree on.
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

-- One row per membership as well, so a membership that moved to a different pair cannot leave two
-- rows claiming it.
CREATE UNIQUE INDEX IF NOT EXISTS membership_identity_key
    ON projection.membership (membership_id);

-- Freshness and lag are read on every projection-backed enforcement check.
CREATE INDEX IF NOT EXISTS membership_applied_mark_idx
    ON projection.membership (applied_mark DESC);

-- The consumer's own position, one row.
--
-- Separate from the membership table because it must survive a membership table with no rows: a
-- consumer that has bootstrapped from an empty estate is in a completely different state from one
-- that never bootstrapped, and only this table can tell them apart.
CREATE TABLE IF NOT EXISTS projection.watermark (
    -- A single row, enforced rather than assumed.
    only_row boolean PRIMARY KEY DEFAULT TRUE CHECK (only_row),

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

INSERT INTO projection.watermark (only_row) VALUES (TRUE) ON CONFLICT DO NOTHING;
