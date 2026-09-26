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
| not an envelope, unknown type, malformed | `400` | no |
| any other failure | `503` | no |

The superseded row is why a dead letter that a newer version has overtaken can never resolve as
`REPLAYED`. `organization-control` closes it as `SUPERSEDED` instead, on the `consumer_applied`
receipt of the newer event (see its TDD-005). The missing marker on this row is what keeps that
distinction honest.

**Three names must agree, and nothing checks them.** `DISPATCH_CONSUMER_NAME`,
`REFERENCE_CONSUMER_NAME`, and the consumer_id registered with `organization-control` must be the
same string. Receipts are keyed by the first, and resolution looks them up by the third. A mismatch
yields receipts that no resolution will ever find.

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
   revocation itself is dead-lettered as poison in the priority lane.
3. The proof asserts that the frontier reports security debt, and that the consumer refuses A and B
   within the frontier cache TTL (`REFERENCE_MAX_PROJECTION_AGE / 4`) plus slack.
4. It replays the revocation, waits for a `consumer_applied` receipt, and resolves it as `REPLAYED`
   through the producer's API.
5. B is served again, and A's refusal reason changes from debt to withdrawal. That change is the
   evidence that the revocation actually landed.

The system itself authors every refusal the proof asserts. The observer only reads them. The CI job
of the same name checks out `organization-control` at the pinned revision. That run is the P0
closure record (`RESPONSE-26`, run 36026176642).

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