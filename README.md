# foundation-reference

The enforcing consumer for **Proof A**: the deployable that answers, with evidence, whether a
membership revocation in `organization-control` becomes a refused operation in a *different
process* — and how long that takes.

It is a separate module and a separate database on purpose. A consumer living inside
`organization-control`, or sharing its database, could be updated by a join instead of by an
event, and the property under test would stop being a property of the event path.

```text
membership.revoked → outbox → dispatcher → broker adapter → THIS → operation refused
```

## Running it

```text
make env        once
make migrate    platform schema (processed_event), then projection.membership
make run        the consumer on 127.0.0.1:8096
make gates      everything CI will run
```

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

## Security classes, not HTTP methods

The fail-open/fail-closed decision is made per **operation security class**, declared at the
route. `GET /payroll` and `GET /passport` are reads with higher confidentiality impact than
most writes, so a policy keyed on read-versus-write is wrong exactly where being wrong costs
most.

| Route | Class | When the projection cannot answer |
| :-- | :-- | :-- |
| `GET /v1/directory/{id}` | `LOW_RISK` | Allowed while the projection is younger than the bound; refused past it |
| `GET /v1/payroll/{id}` | `HIGH_CONFIDENTIALITY` | Refused |
| `POST /v1/administration/{id}` | `PRIVILEGED` | Never reads the projection; asks the authority |
| `POST /v1/deletion/{id}` | `IRREVERSIBLE` | Never reads the projection; asks the authority |

Four properties are held by tests rather than by prose, because widening fail-open is the
change most likely to be made under delivery pressure and least likely to be noticed — it
makes every symptom disappear:

- only `LOW_RISK` may fail open
- the two privileged classes never read the projection
- **a broken read never fails open** — fail-open exists for a projection that is behind, not
  for one that cannot be read; applying it to a database fault would turn a fault into an
  authorisation bypass
- an unreachable authority refuses rather than falling back to the projection

Every route declares its class at declaration, and a test fails if one does not. A class
resolved by lookup with a default would give the wrong answer for some route — and the route
added in a hurry is the one most likely to need the strict one.

## What is deliberately absent

**No row-level security.** RLS in `organization-control` protects authoritative tenant data.
This table holds one boolean and a version per membership, replicated from events. Adding RLS
would imply a tenancy guarantee this deployable is not the authority for.

**No broker.** The intake is plain HTTP so the properties under test are the consumer's, not
a transport's. `outbox.Publisher` is a one-method interface, so the broker lands in one
adapter and the choice is made later, on evidence.

**No authentication yet.** The intake and the operations are open. That is the next commit,
not an oversight: Proof A's first question is whether enforcement happens at all.

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