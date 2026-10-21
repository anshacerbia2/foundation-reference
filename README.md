# foundation-reference

The enforcing consumer for **Proof A**: the deployable that answers, with evidence, whether a
membership revocation in `organization-control` becomes a refused operation in a *different
process*, and how long that takes.

```text
membership.revoked → outbox → organization-control's dispatcher (outbox/httpdelivery) → THIS → operation refused
```

## Design

The design is
[`TDD-foundation-reference-001`](docs/designs/TDD-foundation-reference-001-enforcing-projection-consumer.md)
(parent SAD-004): its two properties, delivery and the evidence it returns, the projection's data
model, the routes and security classes, the consumer's own reconciliation, configuration, the tests and
the system proof, metrics and alerts, and what is deliberately absent. The plan is
[`ROADMAP.md`](ROADMAP.md).

## Running it

```text
make env               once
make migrate           platform schema (processed_event), then projection.membership
make run               the consumer on 127.0.0.1:8096
make gates             build, vet, unit and integration tests
make system-proof      Proof A across real processes (see below); needs .env and a producer checkout
```

CI runs more than `make gates`: mutation gates that break a property and require its test to fail,
and the `system-proof` job.

**A projection made before 2026-10-20 must be rebuilt.** foundation-reference #30 added
`projection.tenant.tenant_version`, `bigint NOT NULL`, so that a Tenant is ordered by the pair
(ADR-ORG-003 §5.5). `make migrate` only creates tables that are missing (`CREATE TABLE IF NOT
EXISTS`), so it leaves an older `projection.tenant` without the column, and every Tenant write then
fails. Rebuild the projection, then seed it again:

```text
go run ./cmd/foundation-reference-migrate -rebuild    drops projection.membership, .tenant and .watermark, then creates them
go run ./cmd/foundation-reference-bootstrap           a snapshot from organization-control, then catch-up
```

Until the bootstrap has run, every projection-backed operation is refused, which is correct: the
consumer holds no positive authority. The system proof builds its databases from zero on every run,
so it needs nothing.

**Deliveries come from organization-control.** To feed a consumer running here, run
`organization-control` (`make issuer`, then `make run`, in that repository) with this consumer as a
delivery target. Its `.env.example` has the block to uncomment:
`ORGANIZATION_DELIVERY_TARGETS=foundation-reference=http://127.0.0.1:8096/v1/deliveries`, the dispatch
credential, and a workload key pair that its dev issuer verifies. Set `REFERENCE_DELIVERY_PRINCIPAL_ID`
here to the principal_id that issuer names. `make deliver F=envelope.json` still posts one envelope by
hand, with a token you supply.

## The system proof

`make system-proof` runs Proof A across real processes (`systemproof/`, build tag `systemproof`). It
needs `.env` and an `organization-control` checkout at the revision in
`systemproof/organization-control.rev`, with no local changes. `SYSTEMPROOF_ORGANIZATION_CONTROL_SRC`
points at it (default `../organization-control`). It drops and recreates two databases on the cluster
in `SYSTEMPROOF_ADMIN_DATABASE_URL`, so that cluster must be one nobody depends on.

`SYSTEMPROOF_UNPINNED=1` lifts the pin and nothing else; such a run is logged `UNPINNED` and never
counts as a closure record. CI runs the pinned proof on every change and daily, and an unpinned one
against `organization-control` main daily. The phases, and why each exists, are in the TDD's §Testing
Strategy.

## Metrics and alerts

With `OTEL_EXPORTER_OTLP_ENDPOINT` set, the consumer exports over OTLP/HTTP; unset, it exports nothing
and says so at startup. The alert rules are `observability/alerts/foundation-reference.rules.yml`. The
series and the alerts are in the TDD's §Operational Notes.
