# Foundation Reference — Roadmap

Execution tracker for this repository only. Architecture lives in
`scnehaux-architecture`; nothing here overrides a SAD, an ADR, or a standard.

This file starts on 2026-10-20. Items 1 to 26 record what was built before it, from the git history
and the README, with each merge's date. Every later change adds or updates a line here in the same
pull request.

## Position in the build order

**This is the enforcing consumer for Proof A, built after its two dependencies.** It answers, with
evidence, whether a Membership revocation in `organization-control` becomes a refused operation in
another process, and how long that takes (README).

- **`foundation-platform` lands first.** This repository pins a released tag (CI's "foundation-platform
  is pinned to a released version"). It uses the inbox guard, the envelope and the verifier.
- **`organization-control` is the producer.** It runs the dispatcher that delivers here
  (`ADR-GLB-018 §5.4`). The system proof pins its revision in `systemproof/organization-control.rev`.
  A daily unpinned run checks its `main`.
- **A change to the consumer contract lands in `organization-control` first, then here.** The
  scnehaux-architecture #102 plan orders it so: foundation-platform `v0.5.0`, then
  organization-control, then this repository.

## Design status

There is no TDD. The README is the design record: the two properties, delivery and evidence, Proof
A, the security classes, the metrics, and what is deliberately absent. Whether this repository needs
a TDD under the owner's living-docs rule is the owner's to decide (item 29).

## Items

Each line gives the item, its status, when, and the architecture section it implements.

| # | Item | Status | Source |
| :-- | :-- | :-- | :-- |
| 1 | ✅ The enforcing consumer, in its own module and database, so the property is the event path's | Done 2026-09-01 (`6960e44`) | ADR-GLB-016 §5.8 |
| 2 | ✅ A duplicate delivery cannot apply twice: `inbox.Guard` in the applying transaction | Done 2026-09-01 | ADR-GLB-016 §5.8 |
| 3 | ✅ An out-of-order delivery cannot undo a newer one: the version guard, with a CI mutation | Done 2026-09-01 | ADR-GLB-016 §5.8 |
| 4 | ✅ Both sides authenticated, as two roles: `foundation-reference.deliver` and `foundation-reference.operate` | Done 2026-09-01 (`49783af`) | STD-IAM-002 §3.5 |
| 5 | ✅ Positive authority: one row per Membership, and absence is never permission | Done 2026-09-02 (`2e68908`, `ac00f36`) | ADR-ORG-001 §5.7 |
| 6 | ✅ Security classes, each with its own staleness budget | Done 2026-09-02 (`14e929c`) | ADR-ORG-001 §5.7 |
| 7 | ✅ Freshness from the producer's frontier and the consumer's own position; a bootstrap command, snapshot then catch-up | Done 2026-09-02 (`d81a5ae`, `aeaed4f`, `f5c6ded`) | ADR-ORG-001 §5.7 |
| 8 | ✅ No class serves past its bound, and an abandoned security delivery refuses every projection-backed class | Done 2026-09-05 (#1) | ADR-ORG-001 §5.7 |
| 9 | ✅ The application receipt, `X-Application-Receipt: applied`, only after the event is applied | Done 2026-09-09 (#3) | ADR-GLB-016 §5.4 |
| 10 | ✅ No receipt for a superseded event | Done 2026-09-17 (#5) | ADR-GLB-016 §5.4 |
| 11 | ✅ Proof A, component layer: resolving the debt restores the bystander and keeps the revocation | Done 2026-09-24 (#6) | ADR-GLB-016 §5.4 |
| 12 | ✅ Proof A, system layer: real processes, pinned producer (`make system-proof`) | Done 2026-09-24 (#7, #8) | ADR-GLB-016 §5.4 |
| 13 | ✅ Pinned and unpinned system proofs; a daily run against the producer's `main` | Done 2026-09-27 (#10) | ADR-GLB-016 §5.4 |
| 14 | ✅ Tenant state enforced, and a named list of types acknowledged rather than dead-lettered | Done 2026-09-27 (#11) | ADR-ORG-001 §5.7 |
| 15 | ✅ Enforcement decisions counted by code, exported, and alerted on | Done 2026-09-28 (#15) | ADR-ORG-001 §5.7 |
| 16 | ✅ Consumer outage, backlog recovery and a timeout before commit, repeatable (phases 7 and 8) | Done 2026-09-28 (#16) | ADR-GLB-016 §5.4 |
| 17 | ✅ Revocation propagation as a distribution, held to the 6 s budget (phase 9) | Done 2026-09-28 (#17) | TDD-organization-control-002 §Enforcement Budget |
| 18 | ✅ Reconciliation repairs applied under the inbox guard (phase 10) | Done 2026-09-28 (#18) | ADR-ORG-001 §5.7 |
| 19 | ✅ The consumer registered by its workload `principal_id`; caller authority from records | Done 2026-10-01 (#19) | ADR-ORG-001 §5.11 |
| 20 | ✅ Per-consumer delivery: subscribed by event type, one delivery row per consumer | Done 2026-10-02 (#20, #21) | ADR-GLB-018 §5.1, §5.2, §5.4 |
| 21 | ✅ The system proof's Tenant administrator holds a grant; a token for another Tenant is refused | Done 2026-10-05 (#24, #25) | ADR-ORG-003 §5.3; ADR-IAM-006 §5.2; STD-IAM-002 §3.5 |
| 22 | ✅ Alert rules moved out of `deploy/` to `observability/alerts/` | Done 2026-10-08 (#27) | STD-GLB-009 §Development Server Deployment rule 12 |
| 23 | ✅ The dispatcher retired: deliveries come from organization-control, and the intake admits its workload alone | Done 2026-10-19 (#29) | ADR-GLB-018 §5.4 and Alternative G (amended 2026-10-15) |
| 24 | ✅ **O2.** The consumer reconciles itself on the interval its registration declares (`internal/reconcile`) | Done 2026-10-20 (#30) | ADR-ORG-001 §5.7 (amended 2026-10-20) |
| 25 | ✅ **O3.** A Tenant is ordered by (`tenant_security_version`, `tenant_version`), and a restore's 10^9 bump is applied | Done 2026-10-20 (#30) | ADR-ORG-003 §5.5 (amended 2026-10-20) |
| 26 | ✅ **O7.** foundation-platform `v0.5.0` pinned; nothing else was required here | Done 2026-10-20 (#30) | STD-GLB-001 1.7.0, 1.8.0; ADR-ORG-007 §5.4 |
| 27 | ✅ This ROADMAP, as the repository's plan | Done 2026-10-20 (#31) | scnehaux-architecture #102 (owner's living-docs rule) |
| 28 | ✅ README: the interval this consumer runs on, the scheduler off without `REFERENCE_AUTHORITY_BASE_URL`, and the rebuild for `tenant_version NOT NULL` | Done 2026-10-20 (#31) | ADR-ORG-001 §5.7; ADR-ORG-003 §5.5 |
| 29 | ⏳ A design record beside the README, if the owner wants one | Open since 2026-10-20; the owner's decision | Owner's living-docs rule |

### Pins and dependency moves

Recorded so a pin's history is readable. Each kept the system proof green against the producer of
its day.

- foundation-platform: `v0.2.3` (#2), `v0.2.6` (#4), `v0.2.10` (#12), `v0.3.1` (#20), `v0.5.0` (#30).
- organization-control: moved with each contract change (#13, #19, #21, #22, #23, #26, #30). It is now
  `6a36b8d` (`systemproof/organization-control.rev`).
- `golang.org/x/net` v0.60.0 (#28, 2026-10-09): GO-2026-6603, -6611, -6612 and -6617, found by
  `govulncheck`.

## Not this repository

- Delivering events: organization-control runs the dispatcher (`ADR-GLB-018 §5.4`).
- The consumer's registration and its interval: a provider registers it in organization-control.
- Alerting on reconciliation age: organization-control's rules, past one and two intervals
  (`ADR-ORG-001 §5.7`).
- Deployment: no environment runs this consumer. It has no `deploy/` directory.
