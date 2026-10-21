---
doc_meta:
  id: TDD-foundation-reference-001
  title: Enforcing Projection Consumer for Membership and Tenant Authority
  owner: Core Platform Team
  version: 0.2.0
  status: proposed
  classification: restricted
  review_cycle_days: 90
  created_date: 2026-10-20
  last_reviewed: 2026-10-21
  parent_sad:
    - SAD-004
---

# Enforcing Projection Consumer for Membership and Tenant Authority

> **Proposed, pending ratification.** This design records what is already built and verified on
> `main` (ROADMAP items 1 to 30). GDC-011 §2.3.4 has every new TDD start at `proposed`. GDC-000 §2.6
> rule 7 makes approval the act of a named human authority on an exact commit, so CI and merge do not
> approve it. At ratification, the status becomes `approved` and the version `1.0.0` in one commit
> (GDC-000 §2.6 rule 6), and `last_reviewed` is that commit's date.

## Purpose

`foundation-reference` is the enforcing consumer for **Proof A**. It answers, with evidence, whether
a Membership revocation in Organization Control becomes a refused operation in a different process,
and how long that takes.

It is its own module with its own database on purpose. A consumer inside Organization Control, or
one sharing its database, could be updated by a join instead of by an event. The property under test
would then stop being a property of the event path.

```text
membership.revoked → outbox → organization-control's dispatcher (outbox/httpdelivery) → THIS → operation refused
```

SAD-004 §7.6 names it as one of the two projection consumers: "The named consumers are
`foundation-reference` (Membership and Tenant) and the Identity Control Service".

## Scope

**In scope:**

- the delivery intake, `POST /v1/deliveries`, and the application receipt it returns;
- the projection of Membership and Tenant state, its bootstrap, its catch-up and its rebuild;
- enforcement per operation security class, on four reference routes;
- the consumer's own reconciliation, on the interval its registration declares;
- the system proof, which runs Proof A across real processes.

**Out of scope:**

- Delivering events. Organization Control runs one dispatcher per consumer and pushes each delivery
  here as its workload (`ADR-GLB-018 §5.4`). This repository shipped a dispatcher of its own until
  2026-10-15, with a static bearer token and a credential to the producer's database.
  `ADR-GLB-018` Alternative G, as amended that day, records its removal.
- Registering the consumer and choosing its interval. A provider registers it in Organization
  Control.
- Alerting on reconciliation age. That is Organization Control's rule, past one and two intervals
  (`ADR-ORG-001 §5.7`).
- Row-level security, a broker, and any deployment. No environment runs this consumer; it has no
  `deploy/` directory (§Security Notes, §Operational Notes).

## Technical Context

| Dependency | What this consumer uses |
| :-- | :-- |
| `foundation-platform` `v0.5.0` | `inbox.Guard`, the event envelope, the token verifier `verify`, `observability`, and the platform migrations (`platform.processed_event`). CI requires a released tag |
| Organization Control | Deliveries from its dispatcher; the snapshot, frontier, registration and reconcile endpoints; the fresh authority check (§API / Interface) |
| The issuer | Tokens for both roles, verified locally against `REFERENCE_JWKS_URL` (`STD-IAM-002 §3.5`) |
| PostgreSQL 17 | Its own database: `platform.processed_event` and the `projection` schema |

**The proof consumer container, for development and CI only (0.2.0, SAD-004 2.7.0 §4.1).** SAD-004
draws `foundation-reference` in its container view as "proof consumer, dev and CI only", with its own
database. The SAD: "`foundation-reference` is a container of the development server and CI, never of
production". It is "the enforcing projection consumer that proves a Membership revocation here becomes
a refused operation in another process", and "It has its own database on purpose: a consumer sharing
this system's database could be updated by a join instead of by an event". "A production deployment
registers no `foundation-reference` consumer and holds no workload credential for it." So in this
repository: the consumer, its database and its registration with Organization Control exist on the
development server and in CI (`systemproof/`); no production configuration, deployment or
registration is written here, and none will be. Its production counterparts are the Identity Control
Service and the products (SAD-004 §7.6).

The delivery path is Direct Durable Delivery over HTTP (`ADR-GLB-016 §5.4`): the source relay calls
a registered target acceptance API, which authenticates the source. Delivery is at least once, so the
consumer deduplicates by event identity (`ADR-GLB-016 §5.8`).

**The dispatcher is Organization Control's, so its `go.mod` decides the dispatcher's
foundation-platform version.** While the dispatcher was built here, this repository's version was
the one that ran. Until `v0.2.10` that was `v0.2.6`, so two dispatcher changes built for Organization
Control never reached the running system: naming the refusing consumer on a dead letter (`v0.2.8`) and
the outbox lease (`v0.2.10`). That skew is gone. This repository's version now matters only for the
inbox guard, the envelope and the verifier.

## Component Design

| Deployable | Does |
| :-- | :-- |
| `cmd/foundation-reference` | The consumer: the intake, the enforced routes, the probes and the reconciliation scheduler, on `REFERENCE_LISTEN_ADDRESS` |
| `cmd/foundation-reference-migrate` | Applies foundation-platform's migrations, then `projection/schema.sql`. `-rebuild` first drops the projection (§Data Model) |
| `cmd/foundation-reference-bootstrap` | Takes a snapshot from Organization Control and seeds the projection at its mark |

| Package | Responsibility |
| :-- | :-- |
| `internal/config` | Reads and validates the environment; refuses to start on any problem |
| `internal/httpapi` | Routes, the two authentication roles, the enforcer (`Decide`), the authority client |
| `internal/projection` | The schema, applying events and repairs, the snapshot seed, the report, the rebuild |
| `internal/frontier` | Reads Organization Control's publication frontier, cached |
| `internal/reconcile` | The scheduler that reconciles this consumer with Organization Control |
| `internal/telemetry` | Metrics, and the test that holds the alert rules to the series produced |

**The publisher classifies; the platform decides.** foundation-platform's `outbox/httpdelivery`, run
by Organization Control, posts the envelope and maps the consumer's answer. foundation-platform's
dispatcher then decides the event's fate:

| Consumer answer | Publisher returns | Dispatcher does |
| :-- | :-- | :-- |
| `2xx` | a receipt | records the delivery receipt |
| `400`, `409`, `422` | poison | dead-letters it at once |
| anything else (`401`, `403`, `429`, `5xx`), or a timeout | unavailable | retries 3 times; then the event is **released** for later delivery, in either lane (foundation-platform v0.2.12). A `401` also drops the cached workload token |

A security event is therefore never abandoned because the consumer was down, only because the
consumer refused it. A timeout is ambiguous, because the consumer may have committed, and it is safe
only because the inbox guard discards the redelivery.

**It drains this consumer's deliveries alone** (`ADR-GLB-018 §5.2`, §5.4). Each event owes each
subscribed consumer a delivery of its own. Organization Control runs one dispatcher per delivery
target, and the one for this consumer claims, leases and settles the deliveries owed to its target
name, so a dead letter is this consumer's. Replay, resolve and waive therefore name the consumer:
`POST /v1/dead-letters/{event_id}/consumers/{consumer}/replay`. The lease works like this:

- a short transaction claims a batch;
- publication happens outside any transaction;
- each outcome commits on its own;
- a crashed dispatcher's rows wait up to 30 s before another worker takes them.

**Three names must agree.** This consumer's name in Organization Control's
`ORGANIZATION_DELIVERY_TARGETS`, `REFERENCE_CONSUMER_NAME`, and the `consumer_id` registered with
Organization Control must be the same string. Receipts are keyed by the first, and resolution looks
them up by the third. A mismatch yields receipts that no resolution will ever find. Two are checked:

- Organization Control runs no dispatcher for a target whose name is not an active registered
  consumer. It waits for the registration instead.
- The bootstrap sends `REFERENCE_CONSUMER_NAME` as the snapshot's consumer. Organization Control
  refuses a consumer it has not registered, and a token naming a different consumer.

The serving consumer's own `REFERENCE_CONSUMER_NAME` keys only its inbox guard, which no resolution
reads, so it is not checked.

## Data Model

`internal/projection/schema.sql` creates the `projection` schema. It is not authoritative: it is a
replica of another system's decision, kept so an enforcement check is answered without a network call.
Its recovery is rebuild from a snapshot, never repair.

| Table | Key | Holds |
| :-- | :-- | :-- |
| `projection.membership` | `membership_id` | `tenant_id`, `principal_id`, `workspace_id` (NULL for Tenant-wide), `membership_status` (`active`, `suspended`, `revoked`), `membership_version`, `applied_mark`, `tenant_security_version`, `applied_at`, `event_id` |
| `projection.tenant` | `tenant_id` | `tenant_status` verbatim, `tenant_security_version`, `tenant_version`, `applied_mark`, `applied_at`, `event_id` (NULL from a snapshot) |
| `projection.watermark` | `consumer` | `snapshot_mark` (NULL until a snapshot completes), `applied_mark`, `bootstrapped_at`, `updated_at` |
| `platform.processed_event` | `(event_id, consumer)` | foundation-platform's inbox record |

- **One row per Membership.** The authority permits one Tenant-wide Membership and one per Workspace
  for the same principal in a Tenant. A first design keyed by `(tenant_id, principal_id)` let one
  event overwrite another, and revoking either reported the principal revoked across the Tenant.
- **Positive state, not a deny-list.** A row holds the status, so an absent row means no positive
  authority, never permission.
- **Every version column is `bigint`, and every version is positive.** A restore's 10^9 bump fits.
- **Indexes.** `membership_active_context_idx` (`tenant_id`, `principal_id`) is partial on `active`, so
  a principal with many revoked Memberships costs the same to check. `membership_context_idx` serves the
  refusal path, which must tell "never seen" from "withdrawn". `membership_applied_mark_idx` serves
  freshness and lag.
- **The watermark is per consumer.** `platform.processed_event` deduplicates per `(event_id,
  consumer)`, so two consumers sharing the database each have their own position. No row is seeded:
  an absent row is the honest "no snapshot taken".
- **`applied_mark` is lag, not convergence.** The producer allocates sequence values before commit, so
  gaps below it are expected.
- **The schema never drops anything.** `schema.sql` uses `CREATE … IF NOT EXISTS`. `rebuild.sql`
  drops `projection.membership`, `projection.tenant` and `projection.watermark`, and runs only on
  `foundation-reference-migrate -rebuild`, a deliberate act. A column added to an existing table
  (`tenant_version`, `bigint NOT NULL`, 2026-10-20) therefore needs a rebuild of a projection made
  before it (README §Running it).

## API / Interface

**Inbound.**

| Route | Caller | Answer |
| :-- | :-- | :-- |
| `GET /healthz` | probe | `200 {"status":"ok"}` |
| `GET /readyz` | probe | `200`, with `projection_age_ms`, or `"projection":"cold"`. It reports the age without judging it: whether an age is acceptable is a per-class question |
| `POST /v1/deliveries` | Organization Control's workload | §Delivery outcomes below. Body at most 1 MiB, one CloudEvents envelope, unknown fields refused |
| `GET /v1/directory/{id}` | caller | `LOW_RISK` |
| `GET /v1/payroll/{id}` | caller | `HIGH_CONFIDENTIALITY` |
| `POST /v1/administration/{id}` | caller | `PRIVILEGED` |
| `POST /v1/deletion/{id}` | caller | `IRREVERSIBLE` |

**Delivery outcomes.** The intake applies the event, its inbox guard and the watermark in one
transaction. Only then does it answer `202` with `X-Application-Receipt: applied`. The dispatcher
turns that marker into `consumer_applied` evidence, and anything else, a bare `2xx` included, into
`transport_accepted`. `outbox.Receipt` has an unexported field, so the dispatcher cannot claim the
strong class on the consumer's behalf.

| Outcome | Status | Marker |
| :-- | :-- | :-- |
| applied | `202` | yes |
| duplicate (already applied) | `202` | yes, because the assertion is true |
| superseded (discarded by the version guard) | `202` | **no**, because nothing was applied |
| acknowledged (a type this consumer knowingly does not act on) | `202` | **no** |
| not an envelope, unknown type, malformed | `400` | no |
| any other failure | `503` | no |

A superseded row is why a dead letter that a newer version has overtaken never resolves as
`REPLAYED`. Organization Control closes it as `SUPERSEDED` instead, on the `consumer_applied` receipt
of the newer event. The missing marker keeps that distinction honest.

**Events applied.** The four Membership types; four Tenant types, `tenant.lifecycle.activated`,
`tenant.security.suspended` (which offboarding also publishes, with `tenant_status` `offboarding`),
`tenant.security.restored` and `tenant.lifecycle.retired`; and `projection.repair.reconciled`. These
are `projection.AppliedEventTypes()`, which the registration subscribes to (`ADR-GLB-018 §5.1`), so a
type outside them is never delivered. A named list of the producer's other types is acknowledged:
Workspace, Organization registry, invitation, offboarding progress and the Tenant intake request
(`internal/projection/projection.go`). Every other type is refused as unknown, a security-class type
added upstream included, so a gap stays visible.

**Outbound, to Organization Control** (`REFERENCE_AUTHORITY_BASE_URL`, with `REFERENCE_AUTHORITY_TOKEN`):

| Call | Used by |
| :-- | :-- |
| `POST /v1/projections/snapshot` | the bootstrap, as `REFERENCE_CONSUMER_NAME` |
| `GET /v1/projections/frontier` | every projection-backed check, cached for a quarter of `REFERENCE_MAX_PROJECTION_AGE` |
| `POST /v1/context/verify` | `PRIVILEGED` and `IRREVERSIBLE`, a fresh authoritative decision (`ADR-ORG-001 §5.7`) |
| `GET /v1/projections/consumers/{consumer_id}` | the scheduler, every check |
| `POST /v1/projections/reconcile` | the scheduler, when a run is due |

**Registration is the subscription.** The consumer is registered with `event_types`, and Organization
Control delivers exactly those. Changing the types clears the consumer's snapshot mark, and it
bootstraps again. The registration also declares `reconciliation_interval_seconds`, from 60 to
604800. This consumer does not register itself: a provider registers it (`POST
/v1/projections/consumers`). The system proof declares one week, then one minute; any other
registration that sends none relies on Organization Control's default of one day.

## Algorithms / Logic

**A duplicate delivery cannot apply an effect twice.** `inbox.Guard` registers the event inside the
transaction that applies it. Registering separately would leave a window where a crash marks an event
processed whose effect rolled back, and the redelivery that would have fixed it is then discarded as a
duplicate.

**An out-of-order delivery cannot undo a newer one.** The version is monotonic and the effect
idempotent, so an older event is discarded by the guard `WHERE excluded.version > membership.version`,
not by broker ordering. That carries a decision for the estate: **per-key ordering is not a
correctness requirement here**, so the broker can be chosen on operational grounds. Removing the guard
produces the real failure:

```text
--- FAIL: TestOutOfOrderDeliveryIsHarmless
    the late delivery reported applied = true, ... want superseded
    version regressed to 5 after an out-of-order delivery, want 9
```

**A Tenant is ordered by the pair (`tenant_security_version`, `tenant_version`)** (`ADR-ORG-003
§5.5`). The security version moves on every transition that changes whether the Tenant's contexts are
valid. Activation is not one, so it carries the same security version as the provisioning state before
it. Ordered by the security version alone, a snapshot that seeded the provisioning Tenant discarded the
activation that followed, and every member stayed refused. `tenant_version` moves on every transition
and breaks the tie. PostgreSQL compares the two as a row: "the row elements are compared left-to-right,
stopping as soon as an unequal or null pair of elements is found" [R1]. identity-control orders by the
same pair.

**A restore's 10^9 bump is applied** (`ADR-ORG-003 §5.5`). A restore to an older point moves every
Tenant's two versions by 10^9 before Organization Control serves, and republishes each withdrawn
Tenant. This consumer applies any higher pair and checks no gap, so the jump is applied like any later
version. Memberships are not bumped: Organization Control advances each past the version this consumer
reports (`POST /v1/projections/advance-versions`).

**Tenant state is enforced.** A member of a Tenant that is suspended, offboarding or retired is
refused, whatever their Membership says, as the authority refuses. So is an active member whose Tenant
state has not arrived: absence is no positive authority. The snapshot seeds each Tenant's state beside
its members. It once wrote a suspension onto the Membership rows, where the Tenant's restoration could
never lift it.

**Bootstrap, then catch-up.** Pages are seeded at the snapshot's mark, and the mark is recorded only
after the last page. Catch-up events after the mark are applied by version comparison, not discarded at
the mark, because the producer allocates its sequence at insert, not commit: a row invisible to the
snapshot can carry a position below the mark. Until a snapshot completes, every projection-backed check
refuses.

**Reconciliation repairs are applied.** `projection.repair.reconciled` carries one sweep's findings for
one consumer, each with the authoritative Membership, or `null` when authority never granted it. The
sweep applies in one transaction under its inbox guard:

- a state is written by the higher-version-wins rule, so a sweep that arrives after a newer event
  changes nothing;
- a `null` removes the row, and only on an `extra` finding;
- a sweep for another consumer is acknowledged.

A `missing` or `mismatch` finding without a state, which a producer from before the state sends, is
refused as poison rather than read as a removal.

**The consumer reconciles itself, on the interval it declares** (`ADR-ORG-001 §5.7`). The party that
holds the copy runs the comparison. Kubernetes: "Controllers that interact with external state find
their desired state from the API server, then communicate directly with an external system to bring the
current state closer in line" [R2].

- Every `REFERENCE_RECONCILE_CHECK_INTERVAL` the scheduler reads the consumer's own registration: the
  declared interval, the age of the last recorded run, and `reconciliation_requested_at`. No copy of the
  interval sits in configuration.
- A run is due when none is recorded, when a restore asked for one, or when the age plus one check
  reaches the interval. So it lands before Organization Control's warning past one interval.
- A run sends `projection.Report`: every active Membership and the mark they correspond to, the higher
  of the snapshot mark and the highest applied position, read in one statement. The repair returns as
  `projection.repair.reconciled`.
- The schedule follows the recorded run, not a timer: "The key metric of a batch job is the last time it
  succeeded" [R3]. A restart, a second replica or a failed run cannot stretch the gap. Two replicas
  checking at once both run, which is harmless. The age is on Organization Control's clock.
- A consumer that has not bootstrapped sends nothing. A `401`, `403` or `404` logs at `WARN`; findings
  log at `WARN`, and an `extra` finding at `ERROR`.
- **Without `REFERENCE_AUTHORITY_BASE_URL` the scheduler is off**, and startup logs at `WARN` "no
  authority configured; this consumer never reconciles itself with organization-control".

**Enforcement: security classes, not HTTP methods.** How much lag an operation may be authorised across
is decided per operation security class, declared at the route. `GET /payroll` is a read with higher
confidentiality impact than most writes, so a read-versus-write policy is wrong where it costs most.

| Class | Behaviour | Staleness budget |
| :-- | :-- | :-- |
| `LOW_RISK` | `use_with_marker` | `REFERENCE_MAX_PROJECTION_AGE` |
| `HIGH_CONFIDENTIALITY` | `fail_closed` | zero |
| `PRIVILEGED` | `revalidate` | never reads the projection; asks the authority |
| `IRREVERSIBLE` | `revalidate` | never reads the projection; asks the authority |

- **No class fails open.** A positive budget is permission to answer from the projection inside it,
  zero is none, and past the budget every class refuses. `LOW_RISK` once served a stale answer with a
  marker nobody read, so a late revocation was refused for sixty seconds and permitted after.
- **Zero is not the window rounded down.** `HIGH_CONFIDENTIALITY` once inherited `LOW_RISK`'s window and
  served confidential data from a thirty-second-old projection. The budget is a property of the policy.
- **Freshness is composed here**, from the producer's frontier and the consumer's own position. The
  producer cannot see which operation is being authorised. Without a frontier, every projection-backed
  class refuses.
- **A broken read never fails open.** A budget is for a projection that is behind, not one that cannot
  be read.
- **An unreachable authority refuses**, never falling back to the projection.
- **A dead-lettered security event refuses every projection-backed class**, outside every budget. A
  dead letter leaves the producer's owed pool by design, so without this "is anything outstanding?"
  would answer no while the withdrawal sits unresolved.
- **The decision is `STD-IAM-002 §3.5` step 8, the current-state check.** It reads this service's own
  projection: an active Membership for the token's principal in an active Tenant, never a version the
  token carries. A token issued for a Tenant (`tenant_id`, `ADR-IAM-006 §5.2`) acts in that Tenant
  alone, so one naming another Tenant than the route's, or a `tenant_id` that is no identifier, is
  refused `403` before anything is read. A token without one is judged on the route's Tenant.
- Every answer carries a `Code` from `httpapi.DecisionCodes`, one per branch of `Decide`.

**Registered baseline: `stale_behavior = use_with_marker`.** Organization Control's registry holds one
`stale_behavior` per consumer, and enforcement here is per class. The registered value is the
**maximum permissiveness** a consumer may use, and an operation may only be stricter, so the baseline
is the loosest behaviour any class uses. It was first registered as `revalidate`, which would have left
`LOW_RISK` more permissive than its own registration.

## Configuration

Read from the process environment only; `.env.example` lists every variable with a placeholder, and
the Makefile loads `.env`. Any problem stops startup.

| Variable | Default | Rule |
| :-- | :-- | :-- |
| `REFERENCE_DATABASE_URL` | — | required |
| `REFERENCE_MIGRATION_DATABASE_URL` | — | required by the migrate command |
| `REFERENCE_LISTEN_ADDRESS` | `127.0.0.1:8096` | |
| `REFERENCE_CONSUMER_NAME` | `foundation-reference` | stable across restarts and replicas; one of the three names that agree |
| `REFERENCE_AUTHORITY_BASE_URL` | empty | empty: no fresh authority, no frontier, no reconciliation; every class refuses |
| `REFERENCE_AUTHORITY_TOKEN` | — | required when an authority is configured |
| `REFERENCE_AUTHORITY_TIMEOUT` | `2s` | |
| `REFERENCE_MAX_PROJECTION_AGE` | `60s` | positive; `LOW_RISK`'s budget; the frontier cache is a quarter of it |
| `REFERENCE_RECONCILE_CHECK_INTERVAL` | `1m` | positive and at most `1m`, the shortest interval Organization Control accepts |
| `REFERENCE_DELIVERY_PRINCIPAL_ID` | — | required, a UUID: the one workload `POST /v1/deliveries` admits |
| `REFERENCE_TOKEN_ISSUER`, `REFERENCE_JWKS_URL` | — | required |
| `REFERENCE_TOKEN_AUDIENCE` | `foundation-reference` | |
| `REFERENCE_TOKEN_MAX_SKEW` | `30s` | at most `60s` (`STD-IAM-002 §3.5`) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | empty | empty: nothing exported, and startup says so |
| `LOG_LEVEL` | `info` | |
| `HTTP_READ_TIMEOUT`, `HTTP_WRITE_TIMEOUT`, `HTTP_REQUEST_TIMEOUT`, `HTTP_SHUTDOWN_GRACE` | `10s`, `30s`, `5s`, `20s` | |
| `HTTP_MAX_IN_FLIGHT` | `256` | |

## Testing Strategy

**Unit and integration** (`make gates`: build, vet, unit, and integration tests against a real
PostgreSQL). Both properties were checked by breaking them. Notable tests:

- `TestOutOfOrderDeliveryIsHarmless`, the version guard;
- `TestAnActivationWithTheSameSecurityVersionIsOrderedByTenantVersion`, the Tenant pair;
- `TestARestoreBumpOfTenToTheNinthIsApplied`, the jump, the next transition, and a late pre-restore
  event discarded;
- `TestOnlyTheConfiguredWorkloadMayDeliver`, the intake's admission;
- `TestEveryBranchDecidesWithItsOwnCode`, one code per branch;
- `TestResolvingTheDebtRestoresTheBystanderAndLeavesTheRevocationEnforced`, Proof A's component layer:
  with A revoked and B active, both are refused while the debt stands, and after resolution B is served
  and A is still refused as withdrawn;
- an `internal/telemetry` test that fails if an alert rule reads a series, code or outcome the consumer
  does not produce.

**Mutation gates in CI.** Each breaks a property and requires its test to fail: no class serves past
its bound; only the configured workload may deliver; the producer's dead-letter debt is load-bearing; a
resolved debt does not release the revocation it delayed; the monotonicity guard; the Tenant ordering's
tie-break; the receipt only where its assertion is true; and one code dropped from the stale alert.
CI also checks the alert rules and runs their unit tests with a pinned `promtool`.

**The system proof** (`make system-proof`, `systemproof/`, build tag `systemproof`) runs Proof A
across real processes:

1. It starts Organization Control at `systemproof/organization-control.rev`, its dev issuer, and this
   consumer, each with a hermetic environment. Organization Control delivers here from its own process,
   through a proxy, with a workload token from the dev issuer's client credentials grant, signed with a
   3072-bit key the test generates. Poll and idle intervals are `200ms` and `300ms`.
2. The proxy answers `422` while A's revocation is delivered, so the revocation is dead-lettered as
   poison in the priority lane, naming this consumer.
3. The frontier reports security debt, and the consumer refuses A and B within the frontier cache TTL
   plus slack.
4. It replays the revocation, waits for a `consumer_applied` receipt, and resolves it as `REPLAYED`.
5. B is served again, and A's refusal changes from debt to withdrawal: the evidence the revocation
   landed.
6. It suspends the Tenant: B is refused with the Tenant's reason within the same bound. It restores
   the Tenant: B is served again.
7. **The consumer goes down** (the proxy answers `503`). B is revoked and five principals are granted.
   B's revocation is recorded `unavailable`, not dead-lettered. When the consumer returns, B is refused
   and all five are served within `BackoffMax` plus one frontier interval.
8. **A delivery times out before commit.** The failed attempt is recorded `unavailable`, the principal
   is still served, and once the hold lifts the revocation lands on the retry, with one receipt and no
   dead letter.
9. **Revocation propagation, as a distribution.** Forty revocations, then twenty with the first
   delivery refused `503`, each timed from outbox commit to the consumer's inbox record on one database
   clock. The run reports p50, p95, p99 and the maximum, and fails if either maximum exceeds the 6 s of
   `TDD-organization-control-002` §Enforcement Budget.
10. **Drift is repaired by the consumer's own reconciliation.** Registered with one week, the first run
    at startup finds nothing. The proof deletes a served row and inserts an active Membership authority
    never granted, then sets `reconciliation_requested_at`. Within one check the consumer reconciles as
    itself, Organization Control records 2 findings, 1 `extra`, and the repair restores the first and
    removes the second. Re-registered with one minute, the next run comes a minute later and finds
    nothing.

The system authors every refusal the proof asserts; the observer only reads them.

| Run | Producer | Consumer | When |
| :-- | :-- | :-- | :-- |
| `system-proof` here | the pin | this commit | every PR, push and daily schedule |
| `system-proof-main` here | Organization Control `main` | this commit | daily schedule and manual dispatch |
| `system-proof` in organization-control | its PR head, or its main | this repository at its pin, or main when scheduled | every PR there, and its daily schedule |

The unpinned runs set `SYSTEMPROOF_UNPINNED=1`, which lifts the pin and nothing else, and are logged
`UNPINNED` so they never pass for a closure record. The P0 closure record is run 36026176642, at
Organization Control `7aa69d7`.

## Security Notes

- **Two roles.** A delivery is a workload writing the projection: scope `foundation-reference.deliver`.
  A caller is a principal asking whether it may act: scope `foundation-reference.operate`, which may not
  write. One role for both would let any caller forge a revocation, or its absence by replaying an older
  version.
- **Only Organization Control's workload may deliver** (`ADR-GLB-018 §5.4`: "The consumer's acceptance
  API admits that workload alone"). The token must carry the delivery scope, name
  `REFERENCE_DELIVERY_PRINCIPAL_ID` as `principal_id`, have `subject_type` `workload`, and carry no
  `tenant_id`; anything else is `403`. The scope alone is not enough, because a realm can grant a scope
  to any client. identity-control's intake holds the same three conditions.
- **Authentication is not optional.** `Routes` refuses to mount without its middlewares, and the
  configuration refuses to start without an issuer and a key set.
- **No row-level security.** RLS in Organization Control protects authoritative Tenant data. This
  projection holds a status and versions per Membership, replicated from events; RLS would imply a
  tenancy guarantee this deployable is not the authority for.
- **No secret in a committed file.** `.env.example` holds placeholders only.

## Performance Notes

A local run on 2026-09-28 measured revocation propagation:

- smooth path: p50 41 ms, p95 89 ms, p99 145 ms, max 145 ms;
- failing path, one retry each: p50 287 ms, p95 375 ms, p99 398 ms, max 398 ms.

That is localhost; CI's numbers are in its job summary. With 40 samples the nearest-rank p99 is the
maximum. The enforcement read is one indexed lookup on a partial index, and the frontier is cached for
a quarter of the projection budget, so a cache can only make an answer look older than it is.

## Operational Notes

With `OTEL_EXPORTER_OTLP_ENDPOINT` set, the consumer exports over OTLP/HTTP.

| Series (Prometheus name) | What it is |
| :-- | :-- |
| `reference_enforcement_decisions_total{class, allowed, code}` | every answer, and why |
| `reference_deliveries_total{outcome}` | `applied`, `duplicate`, `superseded`, `acknowledged`, `refused`, `failed` |
| `reference_projection_age_seconds` | the projection's age; absent while cold |
| `reference_projection_max_age_seconds` | `REFERENCE_MAX_PROJECTION_AGE` |

`observability/alerts/foundation-reference.rules.yml` alerts on a consumer with no snapshot or one that
cannot read its projection, sustained stale refusals of active members, a projection older than its
budget, and a delivery refused as poison. The producer-side alerts (outbox lag, security debt, a
consumer past its reconciliation interval) are Organization Control's.

**Rebuild.** `foundation-reference-migrate -rebuild`, then `foundation-reference-bootstrap`. Until the
bootstrap completes, every projection-backed operation is refused, which is correct.

## Traceability

| Relationship | Target |
| :-- | :-- |
| Parent system | SAD-004 — Scnehaux Organization Control, §7.6 (the named projection consumers) and §7.7 (projection bootstrap) |
| Conforms to | SAD-004 2.7.0 §4.1 — drawn as the proof consumer container with its own database, for development and CI only; production registers no such consumer (0.2.0) |
| Governed by | ADR-GLB-016 §5.4 — Direct Durable Delivery; §5.8 — consumer durability and idempotency |
| Governed by | ADR-GLB-018 §5.1, §5.2, §5.4 — subscriptions, one delivery per consumer, one dispatcher per consumer; Alternative G, amended 2026-10-15 |
| Governed by | ADR-ORG-001 §5.7 — runtime consumption, and a consumer that reconciles itself (amended 2026-10-20); §5.11 — the consumer registered by `principal_id` |
| Governed by | ADR-ORG-003 §5.3 — the proof's granted Tenant administrator; §5.5 — the Tenant pair and the restore bump (amended 2026-10-20) |
| Governed by | ADR-IAM-006 §5.2 — a token's `tenant_id` |
| Conforms to | STD-IAM-002 §3.5 — local verification, skew, and step 8, the current-state check |
| Conforms to | STD-GLB-009 §Development Server Deployment rule 12 — alert rules under `observability/alerts/` |
| Depends on | `TDD-foundation-platform-001` — inbox, envelope, delivery; `TDD-organization-control-002` — Published Events, Enforcement Budget, Reconciliation Interval |
| Plan | `ROADMAP.md` items 1 to 30 |

## References

| Ref | Source |
| :-- | :-- |
| R1 | PostgreSQL Global Development Group, *PostgreSQL 17 Documentation*, Row Constructor Comparison, <https://www.postgresql.org/docs/17/functions-comparisons.html#ROW-WISE-COMPARISON>: "the row elements are compared left-to-right, stopping as soon as an unequal or null pair of elements is found" |
| R2 | Kubernetes, *Controllers*, <https://kubernetes.io/docs/concepts/architecture/controller/>: "Controllers that interact with external state find their desired state from the API server, then communicate directly with an external system to bring the current state closer in line" |
| R3 | Prometheus, *Instrumentation*, §Batch jobs, <https://prometheus.io/docs/practices/instrumentation/#batch-jobs>: "The key metric of a batch job is the last time it succeeded" |
