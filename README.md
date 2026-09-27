# foundation-reference

The enforcing consumer for **Proof A**: the deployable that answers, with evidence, whether a
membership revocation in `organization-control` becomes a refused operation in a *different
process* — and how long that takes.

It is a separate module and a separate database on purpose. A consumer living inside
`organization-control`, or sharing its database, could be updated by a join instead of by an
event, and the property under test would stop being a property of the event path.

```text
membership.revoked → outbox → dispatcher (dispatch.HTTPPublisher) → THIS → operation refused
```

It also hosts that dispatcher. ADR-ORG-001 §5.4 forbids outbound HTTP from `organization-control`,
so the process that reads its outbox and delivers over HTTP lives here, holding a database role that
inherits `organization_dispatch_rt` and nothing more.

## Running it

```text
make env               once
make migrate           platform schema (processed_event), then projection.membership
make run               the consumer on 127.0.0.1:8096
make dispatch          the dispatcher, delivering organization-control's outbox to the consumer
make gates             build, vet, unit and integration tests
make system-proof      Proof A across real processes (see below); needs .env and a producer checkout
```

CI runs more than `make gates`: mutation gates that break a property and require its test to fail,
and the `system-proof` job.

## The two properties it rests on

Both are asserted against a real PostgreSQL, and both were checked by breaking them.

**A duplicate delivery cannot apply an effect twice.** `inbox.Guard` registers the event
inside the same transaction that applies it. Registering separately would leave a window
where a crash marks an event processed whose effect rolled back — and the redelivery that
would have fixed it is then discarded as a duplicate.

**An out-of-order delivery cannot undo a newer one.** The version is monotonic and the effect
is idempotent, so an older event is discarded by the `WHERE excluded.version > membership.version`
guard rather than by broker ordering.

That second one carries a decision for the whole estate: **per-key ordering is not a
correctness requirement here**, so the broker can be chosen on operational grounds. The claim
is only as good as its test, so the test was mutated — removing the guard produces exactly
the real-world failure:

```text
--- FAIL: TestOutOfOrderDeliveryIsHarmless
    the late delivery reported applied = true, ... want superseded
    version regressed to 5 after an out-of-order delivery, want 9
```

## Delivery, and the evidence it returns

**The publisher classifies; the platform decides.** `dispatch.HTTPPublisher` posts the envelope and
maps the consumer's answer. foundation-platform's dispatcher then decides the event's fate:

| Consumer answer | Publisher returns | Dispatcher does |
| :-- | :-- | :-- |
| `2xx` | a receipt | records the delivery receipt |
| `400`, `409`, `422` | poison | dead-letters it at once |
| anything else (`401`, `403`, `429`, `5xx`), or a timeout | unavailable | retries 3 times; then a priority event is **released** for later delivery and a standard one is dead-lettered |

So a security event is never abandoned because the consumer was down, only because the consumer
refused it. A timeout is ambiguous, because the consumer may have committed, and it is safe only
because the inbox guard discards the redelivery.

**Evidence comes from the consumer.** The intake (`POST /v1/deliveries`) applies the event, its
inbox guard, and the watermark in one transaction. Only then does it answer `202` with
`X-Application-Receipt: applied`. The dispatcher turns that marker into `consumer_applied`
evidence, and turns anything else, including a bare `2xx`, into `transport_accepted`.
`outbox.Receipt` has an unexported field, so the dispatcher cannot claim the strong class on the
consumer's behalf.

| Outcome | Status | Marker |
| :-- | :-- | :-- |
| applied | `202` | yes |
| duplicate (already applied) | `202` | yes, because the assertion is true |
| superseded (discarded by the version guard) | `202` | **no**, because nothing was applied |
| acknowledged (a type this consumer knowingly does not act on) | `202` | **no**, because nothing was applied |
| not an envelope, unknown type, malformed | `400` | no |
| any other failure | `503` | no |

**What this consumer applies, and what it acknowledges.** It applies the four Membership types and
four Tenant types:

- `tenant.lifecycle.activated`
- `tenant.security.suspended` (which offboarding also publishes, carrying `tenant_status`
  `offboarding`)
- `tenant.security.restored`
- `tenant.lifecycle.retired`

It acknowledges a named list of the producer's other types: Workspace, Organization registry,
invitation, offboarding progress, and the Tenant intake request. The list is in
`internal/projection/projection.go`. Every other type is refused as unknown, including a
security-class type added upstream and `projection.repair.reconciled`, whose corrections this
consumer cannot yet apply. Refusing them keeps a gap visible rather than silent.

Before the list existed, every type other than Membership was refused. The dispatcher delivers
everything the producer publishes, so every Workspace change, invitation and Tenant suspension
dead-lettered, and none of those incidents could ever be closed.

**Tenant state is enforced.** The authority refuses every member of a Tenant that is not active,
and so does this consumer. `projection.tenant` holds each Tenant's status and is ordered by
`tenant_security_version`. A member of a Tenant that is suspended, offboarding or retired is
refused, whatever their Membership says. So is an active member whose Tenant state has not arrived
yet: absence is no positive authority, for a Tenant as for a Membership. The snapshot seeds each
Tenant's state beside its members. It used to write a suspension onto the membership rows instead,
where the Tenant's restoration, an event about the Tenant, could never lift it.

The superseded row is why a dead letter that a newer version has overtaken can never resolve as
`REPLAYED`. `organization-control` closes it as `SUPERSEDED` instead, on the `consumer_applied`
receipt of the newer event (see its TDD-005). The missing marker on this row is what keeps that
distinction honest.

**The dispatcher is built here, so this repository's `go.mod` decides its foundation-platform
version.** `organization-control` applies the platform schema, and this dispatcher drains it. Until
`v0.2.10` it ran `v0.2.6`, so two dispatcher changes built for `organization-control` never reached
the running system: naming the refusing consumer on a dead letter (`v0.2.8`) and the outbox lease
(`v0.2.10`).

The lease works like this:

- A short transaction claims a batch.
- Publication happens outside any transaction.
- Each outcome commits on its own.
- A crashed dispatcher's rows wait up to 30 s before another worker takes them.

The schema must arrive first: the dispatcher refuses to start against an outbox without the lease
columns. Bump `organization-control` before this repository whenever foundation-platform adds a
migration.

**Three names must agree.** `DISPATCH_CONSUMER_NAME`, `REFERENCE_CONSUMER_NAME`, and the
consumer_id registered with `organization-control` must be the same string. Receipts are keyed by
the first, and resolution looks them up by the third. A mismatch yields receipts that no
resolution will ever find. Two of them are checked:

- **The dispatcher refuses to start** when `DISPATCH_CONSUMER_NAME` is not an active registered
  consumer (`dispatch.CheckRegistered`). organization-control grants its dispatch role read
  access to `consumer_id` and `retired_at` of `projection.consumer` for exactly this.
- **The bootstrap** sends `REFERENCE_CONSUMER_NAME` as the snapshot's consumer. organization-control
  refuses a consumer it has not registered, and a token naming a different consumer.

The serving consumer's own `REFERENCE_CONSUMER_NAME` keys only its inbox guard, which no resolution
reads, so it is not checked.

## Proof A, in two layers

**Component.** `TestResolvingTheDebtRestoresTheBystanderAndLeavesTheRevocationEnforced`
(`internal/httpapi/resolution_transition_integration_test.go`) runs on a real PostgreSQL, with only
the frontier facts stubbed. It seeds two principals: A revoked, B active.

- **While the debt stands:** both are refused. B is refused because of the debt, A because it is
  withdrawn.
- **After resolution:** B is served, and A is still refused as withdrawn.

A CI mutation of the withdrawal check must turn this test red.

**System.** `make system-proof` (`systemproof/`, build tag `systemproof`) runs the whole chain
across real processes:

1. It starts `organization-control` at the revision pinned in `systemproof/organization-control.rev`,
   its dev issuer, this consumer, and the dispatcher, each with a hermetic environment.
2. A proxy in front of the consumer answers `422` while A's revocation is delivered, so the
   revocation itself is dead-lettered as poison in the priority lane, naming this consumer as the
   one that refused it.
3. The proof asserts that the frontier reports security debt, and that the consumer refuses A and B
   within the frontier cache TTL (`REFERENCE_MAX_PROJECTION_AGE / 4`) plus slack.
4. It replays the revocation, waits for a `consumer_applied` receipt, and resolves it as `REPLAYED`
   through the producer's API.
5. B is served again, and A's refusal reason changes from debt to withdrawal. That change is the
   evidence that the revocation actually landed.
6. It suspends the Tenant through the producer's API. B is refused with the Tenant's reason within
   the same bound. Then it restores the Tenant, and B is served again. Both directions are asserted,
   because the restoration is what the snapshot's old shortcut could never deliver.

The system itself authors every refusal the proof asserts. The observer only reads them. The CI job
of the same name checks out `organization-control` at the pinned revision. The P0 closure record
is run 36026176642 (`RESPONSE-26`), at `organization-control` `7aa69d7`. The pin has moved since,
deliberately, each time the pair changed together.

**Pinned and unpinned runs.** The pin keeps a green run reproducible. It also means a producer change
never runs the proof here, so a break shows up only when someone bumps the pin. Three runs cover the
gap (RESPONSE-24 §3):

| Run | Producer | Consumer | When |
| :-- | :-- | :-- | :-- |
| `system-proof` here | the pin | this commit | every PR, push and daily schedule |
| `system-proof-main` here | `organization-control` main | this commit | daily schedule and manual dispatch |
| `system-proof` in `organization-control` | its PR head, or its main | this repository at its pin, or main when scheduled | every PR there, and its daily schedule |

The two unpinned runs set `SYSTEMPROOF_UNPINNED=1`. That lifts the pin and nothing else: the
producer must still be a clean commit, and the run is logged as `UNPINNED` with the pin beside it,
so it never passes for a closure record. A red scheduled run means the pair has drifted. Fix it on
whichever side broke the contract, then bump the pin deliberately.

## Security classes, not HTTP methods

How much lag an operation may be authorised across is decided per **operation security class**,
declared at the route. `GET /payroll` and `GET /passport` are reads with higher confidentiality
impact than most writes, so a policy keyed on read-versus-write is wrong exactly where being
wrong costs most.

**No class fails open.** There was one — `LOW_RISK` served a stale answer and marked it — and
the marker is what made it look acceptable: the access was granted, the label went onto a
response nobody reads, and the class's window bounded nothing. A revocation arriving late was
refused for sixty seconds and permitted from then on. What is left is a single axis: a positive
staleness budget is permission to answer from the projection inside it, zero is no permission at
all, and past the budget every class refuses.

| Route | Class | When the projection cannot answer |
| :-- | :-- | :-- |
| `GET /v1/directory/{id}` | `LOW_RISK` | Allowed while the projection is younger than the bound; refused past it |
| `GET /v1/payroll/{id}` | `HIGH_CONFIDENTIALITY` | Refused |
| `POST /v1/administration/{id}` | `PRIVILEGED` | Never reads the projection; asks the authority |
| `POST /v1/deletion/{id}` | `IRREVERSIBLE` | Never reads the projection; asks the authority |

Five properties are held by tests rather than by prose, because widening permissiveness is the
change most likely to be made under delivery pressure and least likely to be noticed — it
makes every symptom disappear:

- **no class serves past its bound**, and `Policy` may not carry a field that would let one
- the two privileged classes never read the projection
- **a broken read never fails open** — a budget exists for a projection that is behind, not
  for one that cannot be read; applying it to a database fault would turn a fault into an
  authorisation bypass
- an unreachable authority refuses rather than falling back to the projection
- **an authority-bearing event the producer has given up on refuses every projection-backed
  class**, outside every budget — a dead-lettered revocation leaves the producer's owed pool by
  design, so without this the answer to "is anything outstanding?" is *no* while the withdrawal
  sits unresolved

Every route declares its class at declaration, and a test fails if one does not. A class
resolved by lookup with a default would give the wrong answer for some route — and the route
added in a hurry is the one most likely to need the strict one.

## Metrics and alerts

With `OTEL_EXPORTER_OTLP_ENDPOINT` set, the consumer exports over OTLP/HTTP to the OpenTelemetry
Collector. Unset, it exports nothing and says so at startup.

Every enforcement answer carries a `Code` from a fixed set (`httpapi.DecisionCodes`), one per branch
of `Decide`, and `TestEveryBranchDecidesWithItsOwnCode` holds each branch to its own. The metrics
count by that code rather than by the reason text, so labels stay bounded:

| Series (Prometheus name) | What it is |
| :-- | :-- |
| `reference_enforcement_decisions_total{class, allowed, code}` | every answer, and why |
| `reference_deliveries_total{outcome}` | intake outcomes: `applied`, `duplicate`, `superseded`, `acknowledged`, `refused`, `failed` |
| `reference_projection_age_seconds` | the projection's age; absent while it is cold |
| `reference_projection_max_age_seconds` | `REFERENCE_MAX_PROJECTION_AGE` |

`deploy/alerts/foundation-reference.rules.yml` alerts on four conditions:

- a consumer with no snapshot, or one that cannot read its projection;
- sustained stale refusals of active members;
- a projection older than its budget;
- a delivery refused as poison.

The producer-side alerts (outbox lag, security debt, a consumer past its reporting budget) are
organization-control's.

CI checks the rules and runs their unit tests with a pinned `promtool`. A mutation that drops one
code from the stale alert must fail those tests. `internal/telemetry`'s test fails if a rule reads
a series, code or outcome that the consumer does not produce.

## What is deliberately absent

**No row-level security.** RLS in `organization-control` protects authoritative tenant data.
This table holds one boolean and a version per membership, replicated from events. Adding RLS
would imply a tenancy guarantee this deployable is not the authority for.

**No broker.** Delivery is ADR-GLB-016's Direct Durable Delivery profile over plain HTTP, so the
properties under test are the consumer's, not a transport's. `outbox.Publisher` is a one-method
interface, so a broker would land in one adapter. A broker also cannot produce the consumer's
application marker, so adding one would degrade every receipt to `transport_accepted`.
Resolution would then stop finding evidence, loudly, which is intended.

**Authentication is not optional.** `Routes` refuses to mount without its middlewares. The
dispatcher authenticates with scope `foundation-reference.deliver`, and callers with
`foundation-reference.operate`, against the issuer in `REFERENCE_TOKEN_ISSUER`.

## Registered baseline, and why it is use_with_marker

organization-control's consumer registry holds one `stale_behavior` per consumer, while enforcement
here is per operation class. Under the rule the estate settled on -- the registered value is the
**maximum permissiveness** a consumer may use, and an operation may only be stricter -- this consumer
registers:

```text
stale_behavior = use_with_marker
```

It was registered as `revalidate` first, and that was inconsistent with the rule rather than merely
imprecise: `revalidate` is stricter than `use_with_marker`, so LOW_RISK would have been operating
*more permissively* than its own registration allowed. The baseline has to be the loosest behaviour
any class here uses, not the strictest.

| Class | Behaviour | Staleness budget |
| :-- | :-- | :-- |
| `LOW_RISK` | `use_with_marker` | the configured window |
| `HIGH_CONFIDENTIALITY` | `fail_closed` | zero |
| `PRIVILEGED` | `revalidate` | never reads the projection |
| `IRREVERSIBLE` | `revalidate` | never reads the projection |

Zero is not the configured window rounded down. A class that declares no staleness tolerance and
then reads a window from configuration has a declaration that decorates rather than binds -- which
is what happened: HIGH_CONFIDENTIALITY inherited LOW_RISK's sixty seconds and served confidential
data from a thirty-second-old projection.