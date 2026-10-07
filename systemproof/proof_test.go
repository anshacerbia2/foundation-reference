//go:build systemproof

package systemproof

// Proof A, across the process boundary, with the one gate the principal review froze as P0.
//
// # The chain under test
//
//	organization-control  grants A and B, revokes A        (real API, real outbox)
//	dispatcher            delivers through a proxy         (real dispatcher, real classification)
//	proxy                 answers 422 to A's revocation    (the only non-production component)
//	organization-control  dead-letters it as poison        (real decide(), real platform.dead_letter)
//	frontier              reports SecurityDebt             (real HTTP, real cache on the consumer)
//	consumer              refuses A and B for the debt     (real enforcement, read over HTTP)
//	operator              replays A's revocation           (real replay, proxy now passing through)
//	consumer              applies it, emits the receipt    (real projection, real header)
//	dispatcher            records consumer_applied         (real receipt)
//	operator              resolves as REPLAYED             (real resolver, real resolution role)
//	consumer              serves B, refuses A as withdrawn (after the frontier cache expires)
//	organization-control  suspends and restores the Tenant (the consumer refuses, then serves B)
//	proxy                 answers 503: the consumer is down (a revocation and a backlog queue)
//	dispatcher            retries and releases, never dead-letters (an outage is not poison)
//	consumer              receives the whole backlog on recovery (bounded by BackoffMax)
//	proxy                 holds one delivery past the publish timeout (never forwarded)
//	dispatcher            retries it, and it is applied exactly once (one receipt)
//	organization-control  revokes 60 more, 20 of them through a failing first delivery
//	observer              reports commit-to-applied p50/p95/p99/max for both paths (6 s budget)
//
// # Why a proxy, and why it answers 422
//
// A Membership revocation is published in the priority lane, and foundation-platform's dispatcher
// never dead-letters a priority row for unavailability: an outage releases it back to the pool to
// be tried for as long as the outage lasts. Stopping the consumer, cutting the network, or
// answering 401 all produce an outage. The only route to a security dead letter is poison, and the
// publisher classifies poison as a 400, 409 or 422 from the consumer.
//
// A switch inside the consumer that made it refuse would have been simpler and is refused on
// purpose: a switch that can make a consumer reject a revocation is a switch that, left on in
// production, manufactures a dead letter for every revocation -- and one unresolved security dead
// letter refuses every projection-backed read in the estate. The proxy is outside the consumer and
// outside every build that ships. In the recovery phase it forwards bytes unchanged, so the
// delivery that matters reaches the real consumer through the real contract.
//
// # Why A's refusal reason MUST change
//
// The revocation that is poisoned is A's own. So while the debt stands the consumer has never seen
// it: A's row is still active, and A is refused because the consumer cannot vouch for its model,
// not because A is withdrawn. After recovery A is refused because A is withdrawn. That transition,
// debt -> withdrawal, is the only evidence in this proof that the dead-lettered revocation was
// eventually delivered and enforced. Without it the proof shows a debt appearing and disappearing,
// which a system that lost the revocation entirely would also show.
//
// (The component proof in internal/httpapi asserts the opposite -- A's reason does NOT change --
// and both are right: there, A's revocation had already been applied before the debt existed.)

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fdb "github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/outbox"

	"github.com/anshacerbia2/foundation-reference/internal/projection"
)

const (
	// The dev issuer's address is a constant in organization-control's cmd/organization-devissuer,
	// not configuration, so it is a constant here too. The proof checks the port is free before it
	// starts rather than discovering a stale issuer by way of 401s.
	issuerAddress = "127.0.0.1:8098"
	issuerURL     = "http://" + issuerAddress

	// Not the development ports (8099, 8096), so a proof run beside a developer's running services
	// fails on nothing but the issuer.
	producerAddress = "127.0.0.1:18099"
	consumerAddress = "127.0.0.1:18096"

	// The consumer identity. It has to agree across three places that are configured
	// independently: the registration with the producer, the consumer's own name, and the
	// dispatcher's DISPATCH_CONSUMER_NAME. A disagreement between them is one of the failures this
	// proof exists to catch, so all three are set from this one constant rather than typed.
	consumerName = "foundation-reference"

	// The consumer's workload Principal. organization-control recognizes a consumer token by its
	// principal_id, registered with the consumer (organization-control ADR-ORG-001 §5.11), and its
	// dev issuer mints role=consumer tokens naming this one.
	consumerPrincipal = "55555555-5555-4555-8555-55555555555c"

	// Tenant A from organization-control's scripts/ci-fixture.sql, seeded active. Seeding the Tenant
	// is setup: the chain under test starts at a Membership.
	tenantID = "11111111-1111-4111-8111-11111111111a"

	producerDatabase = "organization_systemproof"
	consumerDatabase = "reference_systemproof"

	// The owner organization-control's own CI builds its database under. Deliberately the same, so
	// the producer database here is built the way the producer's CI builds it.
	producerOwner         = "organization"
	producerOwnerPassword = "organization"

	revokedType = "com.scnehaux.organization.membership.security.revoked"

	// LOW_RISK's window, handed to the consumer process. The frontier cache interval is derived
	// from it -- see frontierTTL.
	maxProjectionAge = 40 * time.Second

	// Slack above a bound, for the dispatcher's claim interval and a round trip. Small and named,
	// because a generous slack is how a bounded-propagation assertion quietly becomes "eventually".
	slack = 5 * time.Second

	// The dispatcher's publish timeout, short so the timeout phase takes seconds rather than the
	// default's minutes of retries.
	publishTimeout = time.Second

	// foundation-platform's BackoffMax: the longest a released priority row waits before its next
	// attempt, so the longest a recovered consumer waits for the backlog to resume.
	backoffMax = 30 * time.Second

	// The backlog built while the consumer is down, beside the revocation.
	backlogSize = 5
)

// frontierTTL is the consumer's frontier cache interval, computed the way cmd/foundation-reference
// computes it: a quarter of the LOW_RISK window.
//
// The proof asserts propagation against THIS number, not against a sleep. If the composition root
// changes the ratio, the bound here becomes wrong and the proof fails -- which is correct: the
// propagation delay is part of the seam, and a change to it should be seen.
func frontierTTL() time.Duration { return maxProjectionAge / 4 }

// ---------------------------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------------------------

func TestProofAAcrossTheProcessBoundary(t *testing.T) {
	env := loadEnvironment(t)
	record := recordRevisions(t, env)
	timeline := newTimeline(t)
	t.Cleanup(func() { writeSummary(t, env, record, timeline) })

	bins := buildEverything(t, env)
	timeline.mark("binaries built")

	buildProducerDatabase(t, env, bins)
	buildConsumerDatabase(t, env, bins)
	timeline.mark("databases built")

	requirePortFree(t, issuerAddress, "the dev issuer")
	requirePortFree(t, producerAddress, "organization-control")
	requirePortFree(t, consumerAddress, "foundation-reference")

	start(t, env, "issuer", bins.issuer, nil)
	waitHTTP(t, issuerURL+"/certs", 20*time.Second)

	start(t, env, "organization-control", bins.producer, env.producerConfig())
	waitHTTP(t, "http://"+producerAddress+"/readyz", 30*time.Second)
	timeline.mark("organization-control ready")

	api := &client{t: t, http: &http.Client{Timeout: 15 * time.Second}}
	provider := api.token("role=provider")

	// --- Setup: the consumer is registered and two principals hold active memberships. ---------

	api.expect(http.StatusCreated, http.MethodPost, producerURL("/v1/projections/consumers"), provider,
		map[string]any{
			"consumer_id":              consumerName,
			"principal_id":             consumerPrincipal,
			"projection_version":       "v1",
			"max_accepted_age_seconds": int(maxProjectionAge / time.Second),
			"stale_behavior":           "fail_closed",
			// The registration is the subscription (ADR-GLB-018 §5.1): the producer owes this
			// consumer a delivery of exactly the types it applies.
			"event_types": projection.AppliedEventTypes(),
		})

	// The Tenant's administrator. A token's tenant_id selects a Tenant and confers nothing
	// (organization-control ADR-ORG-003): a provider makes the administrator, which gives it a
	// Membership in the Tenant with the grant, and its token carries acr aal2.
	administrator, err := id.NewV7()
	if err != nil {
		t.Fatalf("minting the administrator: %v", err)
	}
	made := api.expect(http.StatusCreated, http.MethodPost, producerURL("/v1/tenants/"+tenantID+"/administrators"),
		provider, map[string]any{"principal_id": administrator.String()})
	if created, _ := made["membership_created"].(bool); !created {
		t.Fatalf("the first administrator's grant made no Membership: %v", made)
	}
	tenant := api.token("role=tenant&tenant_id=" + tenantID + "&principal_id=" + administrator.String())
	timeline.mark("administrator %s granted in organization-control", administrator)

	a := grant(api, tenant)
	b := grant(api, tenant)
	timeline.mark("A and B granted in organization-control (A=%s, B=%s)", a.principal, b.principal)

	// A member is not an administrator: A's own token for the Tenant administers nothing.
	api.expect(http.StatusForbidden, http.MethodPost, producerURL("/v1/memberships"),
		api.token("role=tenant&tenant_id="+tenantID+"&principal_id="+a.principal), map[string]any{})
	timeline.mark("A, a member and not an administrator, refused at organization-control")

	// The consumer, bootstrapped from a real snapshot, then the delivery path behind the proxy.
	consumerToken := api.token("role=consumer")
	run(t, env, "bootstrap", bins.bootstrap, env.consumerConfig(consumerToken))
	start(t, env, "foundation-reference", bins.consumer, env.consumerConfig(consumerToken))
	waitHTTP(t, "http://"+consumerAddress+"/readyz", 30*time.Second)

	proxy := newPoisonProxy(t, "http://"+consumerAddress)
	start(t, env, "dispatcher", bins.dispatcher, env.dispatcherConfig(proxy.url()+"/v1/deliveries",
		api.token("role=delivery")))
	timeline.mark("consumer bootstrapped; dispatcher delivering through the proxy (pass-through)")

	producerDB := openProducer(t, env)

	// Baseline. Without it the debt phase could be refusing for a reason that was always there --
	// a consumer that never served B would "refuse B under debt" too.
	waitFrontier(t, api, provider, "the catch-up deliveries to drain", func(f frontierFacts) bool {
		return !f.Unpublished && !f.SecurityDebt
	})
	baselineA := waitDecision(t, api, a, 2*frontierTTL()+slack, "A to be served at baseline", allowed)
	baselineB := waitDecision(t, api, b, 2*frontierTTL()+slack, "B to be served at baseline", allowed)
	timeline.mark("baseline: A allowed (%s), B allowed (%s)", baselineA.Reason, baselineB.Reason)

	// --- Phase one: A's revocation is poisoned into a real security dead letter. --------------

	proxy.poison.Store(true)
	revoke(api, tenant, a)
	timeline.mark("A revoked in organization-control; the proxy is answering 422")

	letter := waitDeadLetter(t, producerDB, a.membership)
	proxy.poison.Store(false) // nothing else needs to be refused; the incident now exists
	timeline.mark("dead letter %s: failure_class=%s priority=%d consumer=%q (proxy rejected %d delivery(s))",
		letter.eventID, letter.failureClass, letter.priority, letter.consumer, proxy.rejected.Load())

	// The two properties C1 turned on. If either fails, this is not the state the gate describes.
	if letter.failureClass != "poison" {
		t.Fatalf("the dead letter's failure class is %q, want poison: the proof reached a dead letter "+
			"by some route other than the one it claims", letter.failureClass)
	}
	if letter.priority != outbox.PriorityHigh {
		t.Fatalf("the dead-lettered revocation sits in lane %d, want the priority lane %d: a revocation "+
			"that did not take the reserved lane would queue behind lifecycle traffic",
			letter.priority, outbox.PriorityHigh)
	}
	// The dispatcher names the consumer that refused the event (foundation-platform v0.2.8), which
	// is what lets organization-control attribute the debt to this consumer rather than to everyone
	// and lets a retired consumer's incident be waived. Until this dispatcher moved past v0.2.6 it
	// wrote nothing here, and only module tests had ever seen the column filled.
	if letter.consumer != consumerName {
		t.Fatalf("the dead letter names consumer %q, want %q: the running dispatcher does not attribute "+
			"the incident, so every consumer carries it as debt", letter.consumer, consumerName)
	}

	waitFrontier(t, api, provider, "the producer to report the security debt", func(f frontierFacts) bool {
		return f.SecurityDebt && f.SecurityDeadLettered >= 1
	})
	timeline.mark("producer frontier: SecurityDebt=true")

	// The consumer reads the frontier through a cache, so the debt reaches its decisions within one
	// cache interval -- bounded, and asserted as a bound.
	debtB := waitDecision(t, api, b, frontierTTL()+slack, "B to be refused for the producer's debt", refusedForDebt)
	debtA := decide(t, api, a)
	timeline.mark("under debt: A %s, B %s", debtA, debtB)

	switch {
	case debtA.Allowed:
		t.Fatalf("A is allowed while its own revocation sits in a dead letter: %s", debtA)
	case !isDebtReason(debtA.Reason):
		t.Fatalf("A is refused for %q while the debt stands, want the producer's debt.\n"+
			"A's revocation has not reached the consumer, so A's row is still active there -- a "+
			"withdrawal reason here would mean the consumer learned of the revocation some other way.",
			debtA.Reason)
	case !debtA.Stale:
		t.Fatalf("A's refusal under debt is not marked stale: %s", debtA)
	}

	// --- Recovery: replay through the now-transparent proxy, then resolve on the evidence. ------

	api.expect(http.StatusAccepted, http.MethodPost,
		producerURL("/v1/dead-letters/"+letter.eventID+"/consumers/"+consumerName+"/replay"), provider, nil)
	timeline.mark("replay accepted")

	receiptConsumer, evidence := waitReceipt(t, producerDB, letter.eventID)
	timeline.mark("receipt recorded: %s for consumer %q", evidence, receiptConsumer)

	// The resolver judges the receipt, not this proof. A receipt under another consumer name, or one
	// carrying transport_accepted, must be refused HERE, by the system, with the system's own reason.
	status, resolution := api.do(http.MethodPost,
		producerURL("/v1/dead-letters/"+letter.eventID+"/consumers/"+consumerName+"/resolve"), provider, nil)
	if status != http.StatusOK {
		t.Fatalf("the resolver refused to close the incident (%d): %v", status, resolution)
	}
	if resolution["resolution_type"] != "REPLAYED" || resolution["consumer"] != consumerName {
		t.Fatalf("the resolution recorded %v, want REPLAYED against %q", resolution, consumerName)
	}
	resolvedAt := time.Now()
	timeline.mark("resolved: %v", resolution["resolution_reference"])

	waitFrontier(t, api, provider, "the producer to clear the security debt", func(f frontierFacts) bool {
		return !f.SecurityDebt
	})
	timeline.mark("producer frontier: SecurityDebt=false")

	// --- Propagation: bounded by the consumer's frontier cache, not by a sleep. ----------------

	servedB := waitDecision(t, api, b, frontierTTL()+slack, "B to be served after resolution", allowed)
	propagation := time.Since(resolvedAt)
	withdrawnA := decide(t, api, a)
	timeline.mark("after recovery: A %s, B %s (B restored %s after resolution, bound %s)",
		withdrawnA, servedB, propagation.Round(time.Millisecond), frontierTTL()+slack)

	switch {
	case withdrawnA.Allowed:
		t.Fatalf("A is allowed after the incident was resolved: closing the incident released the " +
			"revocation it was delaying, which is the failure this whole contract exists to prevent")
	case !isWithdrawalReason(withdrawnA.Reason):
		t.Fatalf("A is refused for %q after recovery, want the withdrawal itself", withdrawnA.Reason)
	case withdrawnA.Stale:
		t.Fatalf("A's refusal is still marked stale after the debt cleared: %s", withdrawnA)
	}

	// The transition. Stated last and on its own because it is the assertion the gate turns on.
	if !isDebtReason(debtA.Reason) || !isWithdrawalReason(withdrawnA.Reason) {
		t.Fatalf("A's refusal reason did not move from the producer's debt to the withdrawal:\n"+
			"  under debt:     %q\n  after recovery: %q", debtA.Reason, withdrawnA.Reason)
	}
	timeline.mark("A's refusal reason moved: debt -> withdrawal")

	// --- Phase three: the Tenant is suspended, and the consumer refuses its members. -----------
	//
	// The authority refuses every member of a Tenant that is not active, whatever their Membership
	// says. The consumer used to refuse Tenant events as unknown types, so a suspension dead-lettered
	// and B went on being served here while the authority refused B. Asserted across the process
	// boundary, and in both directions: the restoration has to lift it, because the snapshot's old
	// shortcut wrote a suspension onto membership rows that no Tenant event could clear.
	// A transition carries the version the caller was shown, so the Tenant is read first.
	current := api.expect(http.StatusOK, http.MethodGet, producerURL("/v1/tenants/"+tenantID), provider, nil)
	suspended := api.expect(http.StatusOK, http.MethodPost, producerURL("/v1/tenants/"+tenantID+"/suspend"),
		provider, map[string]any{"expected_version": versionOf(t, current)})
	suspendedAt := time.Now()
	timeline.mark("tenant %s suspended in organization-control", tenantID)

	refusedB := waitDecision(t, api, b, frontierTTL()+slack, "B to be refused for the suspended tenant",
		refusedForTenant)
	timeline.mark("tenant suspended: B %s (%s after the suspension)", refusedB,
		time.Since(suspendedAt).Round(time.Millisecond))

	api.expect(http.StatusOK, http.MethodPost, producerURL("/v1/tenants/"+tenantID+"/restore"),
		provider, map[string]any{"expected_version": versionOf(t, suspended)})
	restoredAt := time.Now()
	restoredB := waitDecision(t, api, b, frontierTTL()+slack, "B to be served after the tenant is restored",
		allowed)
	timeline.mark("tenant restored: B %s (%s after the restoration)", restoredB,
		time.Since(restoredAt).Round(time.Millisecond))

	// --- Phase four: the consumer is down, a backlog builds, and it drains on recovery. ---------
	//
	// Observed once by hand during Proof A (RESPONSE-7 to RESPONSE-10), repeatable from here. B's
	// revocation is a priority event, so the dispatcher must retry it past its local attempts and
	// release it rather than dead-letter it: an outage is not poison. Five grants queue behind it.
	proxy.down.Store(true)
	revoke(api, tenant, b)
	backlog := make([]principal, 0, backlogSize)
	for i := 0; i < backlogSize; i++ {
		backlog = append(backlog, grant(api, tenant))
	}
	timeline.mark("consumer down: B revoked and %d principals granted, behind a proxy answering 503", backlogSize)

	outage := waitOutboxRow(t, producerDB, b.membership, 30*time.Second,
		"B's revocation to be retried past its local attempts",
		func(r outboxRow) bool { return r.attempts > 3 })
	switch {
	case outage.published:
		t.Fatalf("B's revocation is marked published while every delivery was refused: %+v", outage)
	case outage.failureClass != "unavailable":
		t.Fatalf("B's revocation failed as %q, want unavailable: a consumer outage is not poison", outage.failureClass)
	case deadLetterCount(t, producerDB, b.membership) != 0:
		t.Fatal("B's revocation was dead-lettered during an outage; a priority event must be released instead")
	}
	stillB := decide(t, api, b)
	if isWithdrawalReason(stillB.Reason) {
		t.Fatalf("B is refused as withdrawn while its revocation has not been delivered: %s", stillB)
	}
	timeline.mark("during the outage: B's revocation retried %d times, failure_class=%s, not dead-lettered "+
		"(proxy answered 503 %d times); B %s", outage.attempts, outage.failureClass, proxy.unavailable.Load(), stillB)

	proxy.down.Store(false)
	recoveredAt := time.Now()
	// The bound: the longest a released row can wait for its next attempt, then one frontier cache
	// interval for the consumer's decisions to reflect it.
	recovery := backoffMax + frontierTTL() + slack
	withdrawnB := waitDecision(t, api, b, recovery, "B's revocation to be delivered after the outage",
		func(d decision) bool { return !d.Allowed && isWithdrawalReason(d.Reason) })
	for i, p := range backlog {
		waitDecision(t, api, p, recovery, fmt.Sprintf("backlog principal %d to be served", i+1), allowed)
	}
	waitFrontier(t, api, provider, "the backlog to drain", func(f frontierFacts) bool {
		return !f.Unpublished && !f.SecurityDebt
	})
	timeline.mark("after recovery: B %s; all %d backlog grants served; backlog drained %s after the "+
		"consumer came back (bound %s)", withdrawnB, backlogSize, time.Since(recoveredAt).Round(time.Millisecond), recovery)

	// --- Phase five: a delivery times out before the consumer could commit it. -----------------
	//
	// The proxy holds the request past the dispatcher's publish timeout and never forwards it. The
	// dispatcher cannot know whether the consumer applied it -- that ambiguity is why the consumer
	// deduplicates -- and must retry. Here the answer is known: it was never applied, so the
	// principal is still served until the retry lands, and it lands exactly once.
	target := backlog[0]
	proxy.stall.Store(true)
	revoke(api, tenant, target)
	timeline.mark("delivery stalled past the %s publish timeout: %s revoked", publishTimeout, target.principal)

	timedOut := waitOutboxRow(t, producerDB, target.membership, 30*time.Second,
		"the stalled revocation to be recorded as a failed attempt",
		func(r outboxRow) bool { return r.attempts >= 1 && !r.published })
	if timedOut.failureClass != "unavailable" {
		t.Fatalf("a timed-out delivery failed as %q, want unavailable: a timeout is not poison", timedOut.failureClass)
	}
	notApplied := decide(t, api, target)
	if !notApplied.Allowed && isWithdrawalReason(notApplied.Reason) {
		t.Fatalf("the consumer applied a revocation it never received: %s", notApplied)
	}
	timeline.mark("timed out before commit: attempts=%d failure_class=%s (proxy stalled %d request(s)); target %s",
		timedOut.attempts, timedOut.failureClass, proxy.stalled.Load(), notApplied)

	proxy.stall.Store(false)
	releasedAt := time.Now()
	appliedTarget := waitDecision(t, api, target, recovery, "the stalled revocation to be delivered on retry",
		func(d decision) bool { return !d.Allowed && isWithdrawalReason(d.Reason) })
	delivered := waitOutboxRow(t, producerDB, target.membership, recovery, "the retried revocation to be published",
		func(r outboxRow) bool { return r.published })
	if receipts := receiptCount(t, producerDB, delivered.eventID); receipts != 1 {
		t.Fatalf("the retried revocation has %d delivery receipts, want exactly one", receipts)
	}
	if deadLetterCount(t, producerDB, target.membership) != 0 {
		t.Fatal("a delivery that timed out before commit was dead-lettered")
	}
	timeline.mark("after the stall: target %s, published after %d failed attempt(s), one receipt, %s after release",
		appliedTarget, delivered.attempts, time.Since(releasedAt).Round(time.Millisecond))

	// --- Phase nine: revocation propagation, as a distribution. ---------------------------------
	//
	// One localhost sample was all Proof A had (RESPONSE-6). Measured here from the revocation's
	// outbox commit to the consumer's inbox record of it: both timestamps are now() on the same
	// PostgreSQL server, so the difference is on one clock. That is the part of the enforcement
	// budget the dispatcher and the consumer own (TDD-organization-control-002 §Enforcement Budget:
	// commit to claim 1 s, dispatch to applied 5 s). Accept to commit happens inside one request and
	// is not measured here.
	consumerDB := openConsumer(t, env)
	smooth := measurePropagation(t, api, tenant, producerDB, consumerDB, smoothSamples)
	proxy.flaky.Store(true)
	failing := measurePropagation(t, api, tenant, producerDB, consumerDB, failingSamples)
	proxy.flaky.Store(false)

	for _, run := range []struct {
		name    string
		samples []latencySample
	}{{"smooth", smooth}, {"failing (first delivery of each refused 503)", failing}} {
		d := distributionOf(run.samples)
		timeline.mark("propagation, commit to applied, %s path, n=%d: p50 %s  p95 %s  p99 %s  max %s (budget %s)",
			run.name, len(run.samples), d.p50, d.p95, d.p99, d.max, propagationBudget)
		if d.max > propagationBudget {
			t.Errorf("%s path: the slowest revocation took %s from commit to applied, past the %s budget",
				run.name, d.max, propagationBudget)
		}
	}
	// The failing path must actually have failed, or its numbers describe the smooth one twice.
	for _, s := range failing {
		if s.failedAttempts < 1 {
			t.Fatalf("a failing-path revocation (%s) was delivered on its first attempt; the path under "+
				"measurement is not the failing one", s.eventID)
		}
	}

	// --- Phase ten: the consumer's projection drifts, and reconciliation repairs it. -----------
	//
	// organization-control ROADMAP item 19. The consumer loses a Membership authority holds, and
	// gains one authority never granted -- the privilege escalation reconciliation exists to catch.
	// Its report goes to the producer, which publishes one repair carrying the authoritative state;
	// the consumer applies it, restoring the first and removing the second.
	lost := grant(api, tenant)
	waitDecision(t, api, lost, recovery, "a new principal to be served before its row is lost", allowed)
	consumerExec(t, consumerDB, `DELETE FROM projection.membership WHERE membership_id = $1::uuid`, lost.membership)
	waitDecision(t, api, lost, frontierTTL()+slack, "the principal whose row was lost to be refused",
		func(d decision) bool { return !d.Allowed })

	inventedPrincipal, inventedMembership := newIdentifier(t), newIdentifier(t)
	consumerExec(t, consumerDB, `INSERT INTO projection.membership
	    (membership_id, tenant_id, principal_id, membership_status, membership_version, applied_mark,
	     tenant_security_version, applied_at, event_id)
	    VALUES ($1::uuid, $2::uuid, $3::uuid, 'active', 1, 1, 1, now(), gen_random_uuid())`,
		inventedMembership, tenantID, inventedPrincipal)
	invented := principal{principal: inventedPrincipal, membership: inventedMembership,
		operate: api.token("role=operate&subject=" + inventedPrincipal)}
	escalated := waitDecision(t, api, invented, frontierTTL()+slack,
		"the invented Membership to be served, which is the drift", allowed)
	timeline.mark("drift: %s's row lost (refused); an invented Membership served (%s)", lost.principal, escalated)

	report := consumerReport(t, consumerDB)
	sweep := api.expect(http.StatusOK, http.MethodPost, producerURL("/v1/projections/reconcile"), provider, report)
	classes := findingClasses(sweep)
	if classes[lost.membership] != "missing" || classes[inventedMembership] != "extra" {
		t.Fatalf("the sweep classified the lost row %q and the invented one %q, want missing and extra: %v",
			classes[lost.membership], classes[inventedMembership], sweep)
	}
	sweptAt := time.Now()
	timeline.mark("reconciled: %d finding(s), the lost row missing, the invented one extra", len(classes))

	restored := waitDecision(t, api, lost, recovery, "the lost Membership to be repaired", allowed)
	removed := waitDecision(t, api, invented, recovery, "the invented Membership to be removed",
		func(d decision) bool { return !d.Allowed })
	timeline.mark("repaired %s after the sweep: lost row %s; invented %s",
		time.Since(sweptAt).Round(time.Millisecond), restored, removed)
}

func newIdentifier(t *testing.T) string {
	t.Helper()
	minted, err := id.NewV7()
	if err != nil {
		t.Fatalf("minting an identifier: %v", err)
	}
	return minted.String()
}

// consumerExec changes the consumer's projection directly: the drift under test, which no API makes.
func consumerExec(t *testing.T, consumer *fdb.Pool, statement string, args ...any) {
	t.Helper()
	if err := consumer.InTx(context.Background(), func(ctx context.Context, tx fdb.Tx) error {
		_, err := tx.Exec(ctx, statement, args...)
		return err
	}); err != nil {
		t.Fatalf("changing the consumer's projection: %v", err)
	}
}

// consumerReport is the consumer's account of its active projection at its applied mark, in the
// reconcile route's shape.
func consumerReport(t *testing.T, consumer *fdb.Pool) map[string]any {
	t.Helper()
	var mark int64
	var rows []map[string]any
	if err := consumer.InTx(context.Background(), func(ctx context.Context, tx fdb.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT applied_mark FROM projection.watermark WHERE consumer = $1`,
			consumerName).Scan(&mark); err != nil {
			return err
		}
		result, err := tx.Query(ctx, `SELECT membership_id::text, membership_version FROM projection.membership
		    WHERE membership_status = 'active' ORDER BY membership_id`)
		if err != nil {
			return err
		}
		defer result.Close()
		for result.Next() {
			var membership string
			var version int64
			if err := result.Scan(&membership, &version); err != nil {
				return err
			}
			rows = append(rows, map[string]any{"membership_id": membership, "membership_version": version})
		}
		return result.Err()
	}); err != nil {
		t.Fatalf("reading the consumer's projection for its report: %v", err)
	}
	return map[string]any{"consumer_id": consumerName, "mark": mark, "rows": rows}
}

func findingClasses(sweep map[string]any) map[string]string {
	out := map[string]string{}
	findings, _ := sweep["findings"].([]any)
	for _, raw := range findings {
		f, _ := raw.(map[string]any)
		membership, _ := f["membership_id"].(string)
		class, _ := f["classification"].(string)
		out[membership] = class
	}
	return out
}

const (
	smoothSamples  = 40
	failingSamples = 20

	// Commit to dispatch claim (1 s) plus dispatch to consumer applied (5 s).
	propagationBudget = 6 * time.Second
)

type latencySample struct {
	eventID        string
	latency        time.Duration
	failedAttempts int
}

// measurePropagation grants n principals, waits until the consumer holds them, revokes them one after
// another, and returns each revocation's commit-to-applied latency.
func measurePropagation(t *testing.T, api *client, tenantToken string, producer, consumer *fdb.Pool, n int) []latencySample {
	t.Helper()
	granted := make([]principal, 0, n)
	memberships := make([]string, 0, n)
	for i := 0; i < n; i++ {
		p := grant(api, tenantToken)
		granted = append(granted, p)
		memberships = append(memberships, p.membership)
	}
	waitConsumerRows(t, consumer, memberships, "active", 60*time.Second)

	for _, p := range granted {
		revoke(api, tenantToken, p)
		time.Sleep(50 * time.Millisecond)
	}
	waitConsumerRows(t, consumer, memberships, "revoked", 60*time.Second)

	type committed struct {
		eventID  string
		at       time.Time
		attempts int
	}
	var rows []committed
	if err := producer.InTx(context.Background(), func(ctx context.Context, tx fdb.Tx) error {
		result, err := tx.Query(ctx, `
			SELECT o.event_id::text, o.created_at, d.attempts
			  FROM platform.outbox o
			  JOIN platform.outbox_delivery d
			    ON d.created_at = o.created_at AND d.event_id = o.event_id AND d.consumer = $3
			 WHERE o.event_type = $1 AND o.payload->>'membership_id' = ANY ($2::text[])`,
			revokedType, memberships, consumerName)
		if err != nil {
			return err
		}
		defer result.Close()
		for result.Next() {
			var c committed
			if err := result.Scan(&c.eventID, &c.at, &c.attempts); err != nil {
				return err
			}
			rows = append(rows, c)
		}
		return result.Err()
	}); err != nil {
		t.Fatalf("reading the revocations' commits: %v", err)
	}
	if len(rows) != n {
		t.Fatalf("found %d revocations in the outbox, want %d", len(rows), n)
	}

	samples := make([]latencySample, 0, n)
	for _, c := range rows {
		var applied time.Time
		if err := consumer.InTx(context.Background(), func(ctx context.Context, tx fdb.Tx) error {
			return tx.QueryRow(ctx, `SELECT processed_at FROM platform.processed_event
			    WHERE event_id = $1::uuid AND consumer = $2`, c.eventID, consumerName).Scan(&applied)
		}); err != nil {
			t.Fatalf("reading the consumer's record of %s: %v", c.eventID, err)
		}
		samples = append(samples, latencySample{eventID: c.eventID, latency: applied.Sub(c.at), failedAttempts: c.attempts})
	}
	return samples
}

// waitConsumerRows waits until the consumer's projection holds every membership in the given status.
func waitConsumerRows(t *testing.T, consumer *fdb.Pool, memberships []string, status string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		var n int
		if err := consumer.InTx(context.Background(), func(ctx context.Context, tx fdb.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM projection.membership
			    WHERE membership_id::text = ANY ($1::text[]) AND membership_status = $2`, memberships, status).Scan(&n)
		}); err != nil {
			t.Fatalf("reading the consumer's projection: %v", err)
		}
		if n == len(memberships) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited %s for %d memberships to be %s at the consumer; %d are", within, len(memberships), status, n)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

type distribution struct{ p50, p95, p99, max time.Duration }

// distributionOf reports nearest-rank percentiles, rounded to the millisecond.
func distributionOf(samples []latencySample) distribution {
	latencies := make([]time.Duration, len(samples))
	for i, s := range samples {
		latencies[i] = s.latency
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	rank := func(p float64) time.Duration {
		index := int(float64(len(latencies))*p+0.999999) - 1
		if index < 0 {
			index = 0
		}
		return latencies[index].Round(time.Millisecond)
	}
	return distribution{p50: rank(0.50), p95: rank(0.95), p99: rank(0.99), max: latencies[len(latencies)-1].Round(time.Millisecond)}
}

func openConsumer(t *testing.T, env environment) *fdb.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := fdb.Open(ctx, fdb.Config{
		Name:     "systemproof-consumer-observer",
		DSN:      withDatabase(env.adminDSN, consumerDatabase),
		MaxConns: 2,
	})
	if err != nil {
		t.Fatalf("opening the consumer database for observation: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// outboxRow is the latest revocation of one Membership in the producer's outbox.
type outboxRow struct {
	eventID      string
	attempts     int
	failureClass string
	published    bool
}

func waitOutboxRow(t *testing.T, pool *fdb.Pool, membershipID string, within time.Duration, what string,
	want func(outboxRow) bool) outboxRow {
	t.Helper()
	deadline := time.Now().Add(within)
	var last outboxRow
	for {
		found := false
		err := pool.InTx(context.Background(), func(ctx context.Context, tx fdb.Tx) error {
			rows, err := tx.Query(ctx, `
				SELECT o.event_id::text, d.attempts, coalesce(d.failure_class, ''), d.published
				  FROM platform.outbox o
				  JOIN platform.outbox_delivery d
				    ON d.created_at = o.created_at AND d.event_id = o.event_id AND d.consumer = $3
				 WHERE o.event_type = $1 AND o.payload->>'membership_id' = $2
				 ORDER BY o.sequence DESC
				 LIMIT 1`, revokedType, membershipID, consumerName)
			if err != nil {
				return err
			}
			defer rows.Close()
			if rows.Next() {
				found = true
				return rows.Scan(&last.eventID, &last.attempts, &last.failureClass, &last.published)
			}
			return rows.Err()
		})
		if err != nil {
			t.Fatalf("reading platform.outbox: %v", err)
		}
		if found && want(last) {
			return last
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited %s for %s; last row: %+v", within, what, last)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func deadLetterCount(t *testing.T, pool *fdb.Pool, membershipID string) int {
	t.Helper()
	var n int
	if err := pool.InTx(context.Background(), func(ctx context.Context, tx fdb.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM platform.dead_letter
		    WHERE event_type = $1 AND payload->>'membership_id' = $2`, revokedType, membershipID).Scan(&n)
	}); err != nil {
		t.Fatalf("counting dead letters: %v", err)
	}
	return n
}

func receiptCount(t *testing.T, pool *fdb.Pool, eventID string) int {
	t.Helper()
	var n int
	if err := pool.InTx(context.Background(), func(ctx context.Context, tx fdb.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM platform.delivery_receipt WHERE event_id = $1::uuid`,
			eventID).Scan(&n)
	}); err != nil {
		t.Fatalf("counting receipts: %v", err)
	}
	return n
}

// ---------------------------------------------------------------------------------------------
// Environment and revisions
// ---------------------------------------------------------------------------------------------

type environment struct {
	adminDSN       string
	producerSource string
	consumerSource string
	logDir         string
	binDir         string
	allowDirty     bool
	unpinned       bool

	runtimePassword, providerPassword, dispatchPassword, resolutionPassword, consumerPassword string
}

func loadEnvironment(t *testing.T) environment {
	t.Helper()

	required := func(name, why string) string {
		value := strings.TrimSpace(os.Getenv(name))
		if value == "" {
			t.Fatalf("%s is required: %s", name, why)
		}
		return value
	}

	consumerSource, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("locating this repository: %v", err)
	}
	// Relative paths are taken from the repository root, not from the working directory: `go test`
	// runs in the package directory, so "..\organization-control" in .env would otherwise resolve
	// to a directory inside this repository that does not exist.
	fromRoot := func(path string) string {
		if path == "" || filepath.IsAbs(path) {
			return path
		}
		return filepath.Join(consumerSource, path)
	}

	producerSource := fromRoot(strings.TrimSpace(os.Getenv("SYSTEMPROOF_ORGANIZATION_CONTROL_SRC")))
	if producerSource == "" {
		producerSource = filepath.Join(consumerSource, "..", "organization-control")
	}
	producerSource = filepath.Clean(producerSource)

	logDir := fromRoot(strings.TrimSpace(os.Getenv("SYSTEMPROOF_LOG_DIR")))
	if logDir == "" {
		logDir = t.TempDir()
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("creating the log directory: %v", err)
	}

	return environment{
		adminDSN: required("SYSTEMPROOF_ADMIN_DATABASE_URL",
			"a superuser connection on the cluster the proof builds its two databases in"),
		producerSource: producerSource,
		consumerSource: consumerSource,
		logDir:         logDir,
		binDir:         t.TempDir(),
		allowDirty:     os.Getenv("SYSTEMPROOF_ALLOW_DIRTY") == "1",
		unpinned:       os.Getenv("SYSTEMPROOF_UNPINNED") == "1",

		// The same names organization-control's own suite uses. These are cluster roles, so a local
		// run must pass the local passwords -- writing different ones would rewrite the credentials
		// the development .env depends on.
		runtimePassword:    required("TEST_RUNTIME_PASSWORD", "organization_app's password on this cluster"),
		providerPassword:   required("TEST_PROVIDER_PASSWORD", "organization_provider_app's password"),
		dispatchPassword:   required("TEST_DISPATCH_PASSWORD", "organization_dispatch_app's password"),
		resolutionPassword: required("TEST_RESOLUTION_PASSWORD", "organization_resolution_app's password"),
		consumerPassword:   required("TEST_CONSUMER_PASSWORD", "organization_consumer_app's password"),
	}
}

type revisions struct {
	producerCommit, consumerCommit     string
	producerPlatform, consumerPlatform string
	consumerDirty                      bool
	unpinned                           bool
}

// recordRevisions pins the system being proven, and refuses to prove anything else.
//
// The closure artifact has to identify the exact system it closed. So the producer checkout must be
// the commit named in organization-control.rev and must be clean: a floating or locally modified
// producer would make a green run a statement about a system nobody can reproduce.
//
// SYSTEMPROOF_UNPINNED=1 lifts the pin, and only the pin, for the two runs that exist to test
// something other than the pinned system: organization-control's own CI, which proves its pull
// request against this consumer, and the scheduled runs against the other side's main, which find
// drift before a pin bump does. Such a run is logged as UNPINNED and is never a closure record. The
// producer must still be a clean commit, so an unpinned run still names the system it ran.
func recordRevisions(t *testing.T, env environment) revisions {
	t.Helper()

	pinBytes, err := os.ReadFile("organization-control.rev")
	if err != nil {
		t.Fatalf("reading the pinned organization-control revision: %v", err)
	}
	pin := strings.TrimSpace(string(pinBytes))

	var out revisions
	out.producerCommit = git(t, env.producerSource, "rev-parse", "HEAD")
	out.unpinned = env.unpinned
	if out.producerCommit != pin && !env.unpinned {
		t.Fatalf("organization-control at %s is %s, and this proof is pinned to %s.\n"+
			"Check out the pinned revision, or change organization-control.rev deliberately -- "+
			"the pin is what makes a green run reproducible.", env.producerSource, out.producerCommit, pin)
	}
	if dirty := git(t, env.producerSource, "status", "--porcelain"); dirty != "" {
		t.Fatalf("organization-control has uncommitted changes, so it is not the pinned revision:\n%s", dirty)
	}

	out.consumerCommit = git(t, env.consumerSource, "rev-parse", "HEAD")
	out.consumerDirty = git(t, env.consumerSource, "status", "--porcelain") != ""
	if out.consumerDirty && !env.allowDirty {
		t.Fatal("foundation-reference has uncommitted changes. A closure run must be of a commit; " +
			"set SYSTEMPROOF_ALLOW_DIRTY=1 for a development run, which is then recorded as dirty")
	}

	out.producerPlatform = platformVersion(t, filepath.Join(env.producerSource, "go.mod"))
	out.consumerPlatform = platformVersion(t, filepath.Join(env.consumerSource, "go.mod"))

	if out.unpinned {
		t.Logf("organization-control  %s (UNPINNED: the pin is %s; this run is not a closure record)",
			out.producerCommit, pin)
	} else {
		t.Logf("organization-control  %s", out.producerCommit)
	}
	t.Logf("foundation-reference  %s%s", out.consumerCommit, map[bool]string{true: " (DIRTY)"}[out.consumerDirty])
	t.Logf("foundation-platform   %s (producer), %s (consumer)", out.producerPlatform, out.consumerPlatform)
	return out
}

func platformVersion(t *testing.T, goMod string) string {
	t.Helper()
	content, err := os.ReadFile(goMod)
	if err != nil {
		t.Fatalf("reading %s: %v", goMod, err)
	}
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		for i, field := range fields {
			if field == "github.com/anshacerbia2/foundation-platform" && i+1 < len(fields) {
				return fields[i+1]
			}
		}
	}
	t.Fatalf("%s names no foundation-platform version", goMod)
	return ""
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s in %s: %v", strings.Join(args, " "), dir, err)
	}
	return strings.TrimSpace(string(out))
}

// ---------------------------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------------------------

type binaries struct {
	producer, producerMigrate, issuer                string
	consumer, consumerMigrate, bootstrap, dispatcher string
}

func buildEverything(t *testing.T, env environment) binaries {
	t.Helper()

	exe := func(name string) string {
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		return filepath.Join(env.binDir, name)
	}
	b := binaries{
		producer:        exe("organization-control"),
		producerMigrate: exe("organization-migrate"),
		issuer:          exe("organization-devissuer"),
		consumer:        exe("foundation-reference"),
		consumerMigrate: exe("foundation-reference-migrate"),
		bootstrap:       exe("foundation-reference-bootstrap"),
		dispatcher:      exe("foundation-reference-dispatcher"),
	}

	build(t, env.producerSource, b.producer, "./cmd/organization-control")
	build(t, env.producerSource, b.producerMigrate, "./cmd/organization-migrate")
	// The issuer exists only under its build tag, which is its safety property: it is absent from
	// every build that ships. The service it authenticates against is built without the tag.
	build(t, env.producerSource, b.issuer, "./cmd/organization-devissuer", "-tags", "devissuer")
	build(t, env.consumerSource, b.consumer, "./cmd/foundation-reference")
	build(t, env.consumerSource, b.consumerMigrate, "./cmd/foundation-reference-migrate")
	build(t, env.consumerSource, b.bootstrap, "./cmd/foundation-reference-bootstrap")
	build(t, env.consumerSource, b.dispatcher, "./cmd/foundation-reference-dispatcher")
	return b
}

func build(t *testing.T, dir, output, pkg string, extra ...string) {
	t.Helper()
	args := append([]string{"build", "-o", output}, extra...)
	args = append(args, pkg)
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	// Each module resolves against its own go.mod. A workspace file above either checkout would
	// silently substitute one side's dependencies for the other's.
	cmd.Env = append(hermetic(), "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building %s in %s: %v\n%s", pkg, dir, err, out)
	}
}

// ---------------------------------------------------------------------------------------------
// Databases -- built the way each repository's own CI builds them
// ---------------------------------------------------------------------------------------------

func buildProducerDatabase(t *testing.T, env environment, b binaries) {
	t.Helper()

	admin := env.adminDSN
	psql(t, admin, "-c", fmt.Sprintf(
		"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%[1]s') "+
			"THEN CREATE ROLE %[1]s LOGIN SUPERUSER PASSWORD '%[2]s'; "+
			"ELSE ALTER ROLE %[1]s LOGIN SUPERUSER PASSWORD '%[2]s'; END IF; END $$;",
		producerOwner, producerOwnerPassword))
	psql(t, admin, "-c", "DROP DATABASE IF EXISTS "+producerDatabase+" WITH (FORCE)")
	psql(t, admin, "-c", "CREATE DATABASE "+producerDatabase+" OWNER "+producerOwner)

	owner := withCredentials(withDatabase(admin, producerDatabase), producerOwner, producerOwnerPassword)
	migrate := map[string]string{"ORGANIZATION_MIGRATION_DATABASE_URL": owner}

	run(t, env, "organization-migrate pre", b.producerMigrate, migrate, "-stage=pre")

	migrations, err := filepath.Glob(filepath.Join(env.producerSource, "migrations", "*.sql"))
	if err != nil {
		t.Fatalf("listing organization-control migrations: %v", err)
	}
	// Filename order, which is the order Atlas and organization-control's CI apply them in.
	sort.Strings(migrations)
	for _, file := range migrations {
		psql(t, owner, "-f", file)
	}

	run(t, env, "organization-migrate post", b.producerMigrate, migrate, "-stage=post")

	psql(t, owner,
		"-v", "runtime_password="+env.runtimePassword,
		"-v", "provider_password="+env.providerPassword,
		"-v", "dispatch_password="+env.dispatchPassword,
		"-v", "resolution_password="+env.resolutionPassword,
		// Ignored by a producer revision whose fixture has no consumer login role, so the harness can
		// supply it before the producer requires it.
		"-v", "consumer_password="+env.consumerPassword,
		"-f", filepath.Join(env.producerSource, "scripts", "ci-fixture.sql"))
}

func buildConsumerDatabase(t *testing.T, env environment, b binaries) {
	t.Helper()
	psql(t, env.adminDSN, "-c", "DROP DATABASE IF EXISTS "+consumerDatabase+" WITH (FORCE)")
	psql(t, env.adminDSN, "-c", "CREATE DATABASE "+consumerDatabase)
	run(t, env, "foundation-reference-migrate", b.consumerMigrate, map[string]string{
		"REFERENCE_MIGRATION_DATABASE_URL": withDatabase(env.adminDSN, consumerDatabase),
	})
}

// psql puts every option before the connection string, which it passes with -d: the Windows psql
// stops parsing options at the first positional argument, so `psql "$DSN" -c ...` reads an empty
// stdin and exits 0 having done nothing.
func psql(t *testing.T, dsn string, args ...string) {
	t.Helper()
	full := append([]string{"-v", "ON_ERROR_STOP=1", "-q"}, args...)
	full = append(full, "-d", dsn)
	cmd := exec.Command("psql", full...)
	cmd.Env = hermetic()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("psql %s: %v\n%s", redact(strings.Join(args, " ")), err, out)
	}
}

func withDatabase(dsn, database string) string {
	parsed, err := url.Parse(dsn)
	if err != nil {
		panic(fmt.Sprintf("the admin DSN is not a URL: %v", err))
	}
	parsed.Path = "/" + database
	return parsed.String()
}

func withCredentials(dsn, user, password string) string {
	parsed, err := url.Parse(dsn)
	if err != nil {
		panic(fmt.Sprintf("the admin DSN is not a URL: %v", err))
	}
	parsed.User = url.UserPassword(user, password)
	return parsed.String()
}

// redact keeps role passwords out of a failure message, which ends up in CI output.
var passwordArgument = regexp.MustCompile(`(_password=)\S+`)

func redact(s string) string { return passwordArgument.ReplaceAllString(s, "${1}***") }

// ---------------------------------------------------------------------------------------------
// Process configuration -- every variable stated, nothing inherited
// ---------------------------------------------------------------------------------------------

func (env environment) producerDSN(user, password string) string {
	return withCredentials(withDatabase(env.adminDSN, producerDatabase), user, password)
}

func (env environment) producerConfig() map[string]string {
	return map[string]string{
		"ORGANIZATION_TENANT_DATABASE_URL":     env.producerDSN("organization_app", env.runtimePassword),
		"ORGANIZATION_PROVIDER_DATABASE_URL":   env.producerDSN("organization_provider_app", env.providerPassword),
		"ORGANIZATION_RESOLUTION_DATABASE_URL": env.producerDSN("organization_resolution_app", env.resolutionPassword),
		// The consumer's own credential, which is what enables consumer authority at the producer.
		"ORGANIZATION_CONSUMER_DATABASE_URL": env.producerDSN("organization_consumer_app", env.consumerPassword),
		"ORGANIZATION_TOKEN_ISSUER":          issuerURL,
		"ORGANIZATION_JWKS_URL":              issuerURL + "/certs",
		// The producer's keyless resource registration, never a client (STD-IAM-002 §3.1).
		"ORGANIZATION_TOKEN_AUDIENCE": "organization-control-api",
		// No claim or role names: the producer reads a caller from the standard's claims and its
		// own records. Its provider is the dev issuer's, whose grant scripts/ci-fixture.sql seeds.
		"ORGANIZATION_LISTEN_ADDRESS": producerAddress,
	}
}

func (env environment) consumerConfig(authorityToken string) map[string]string {
	return map[string]string{
		"REFERENCE_DATABASE_URL":       withDatabase(env.adminDSN, consumerDatabase),
		"REFERENCE_LISTEN_ADDRESS":     consumerAddress,
		"REFERENCE_CONSUMER_NAME":      consumerName,
		"REFERENCE_MAX_PROJECTION_AGE": maxProjectionAge.String(),
		"REFERENCE_AUTHORITY_BASE_URL": "http://" + producerAddress,
		"REFERENCE_AUTHORITY_TOKEN":    authorityToken,
		"REFERENCE_AUTHORITY_TIMEOUT":  "2s",
		"REFERENCE_TOKEN_ISSUER":       issuerURL,
		"REFERENCE_JWKS_URL":           issuerURL + "/certs",
		"REFERENCE_TOKEN_AUDIENCE":     "foundation-reference",
	}
}

func (env environment) dispatcherConfig(endpoint, deliveryToken string) map[string]string {
	return map[string]string{
		"DISPATCH_OUTBOX_DATABASE_URL": env.producerDSN("organization_dispatch_app", env.dispatchPassword),
		"DISPATCH_CONSUMER_ENDPOINT":   endpoint,
		"DISPATCH_CONSUMER_NAME":       consumerName,
		"DISPATCH_DELIVERY_TOKEN":      deliveryToken,
		"DISPATCH_INTERVAL":            "200ms",
		"DISPATCH_IDLE_INTERVAL":       "300ms",
		"DISPATCH_PUBLISH_TIMEOUT":     publishTimeout.String(),
	}
}

// hermetic is the process environment with every service variable removed.
//
// This is the lesson of the config suite that passed locally and failed in CI: `make` loads .env,
// so a developer's shell carries REFERENCE_DATABASE_URL pointing at the development database, and
// a child that inherited it would run the proof against the wrong database while every step
// reported success. Children get the platform's variables (PATH, the Go caches, SystemRoot, which
// Windows needs to open a socket) and exactly the configuration stated for them.
func hermetic() []string {
	var out []string
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		switch {
		case strings.HasPrefix(name, "ORGANIZATION_"),
			strings.HasPrefix(name, "REFERENCE_"),
			strings.HasPrefix(name, "DISPATCH_"),
			strings.HasPrefix(name, "TEST_"),
			strings.HasPrefix(name, "SYSTEMPROOF_"),
			strings.HasPrefix(name, "PG"):
			continue
		}
		out = append(out, entry)
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------------------------

// start launches a long-running process and stops it when the test ends. Its output goes to a file
// in the log directory, and on failure the tail of every log is printed, because a red proof whose
// cause is inside a child process is otherwise a red proof with no cause.
func start(t *testing.T, env environment, name, binary string, config map[string]string, args ...string) {
	t.Helper()

	logPath := filepath.Join(env.logDir, strings.ReplaceAll(name, " ", "-")+".log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("creating %s: %v", logPath, err)
	}

	cmd := exec.Command(binary, args...)
	cmd.Env = withConfig(config)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting %s: %v", name, err)
	}

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = logFile.Close()
		if t.Failed() {
			t.Logf("---- last lines of %s (%s) ----\n%s", name, logPath, tail(logPath, 40))
		}
	})
}

// run executes a process to completion and fails the test if it does not succeed.
func run(t *testing.T, env environment, name, binary string, config map[string]string, args ...string) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Env = withConfig(config)
	out, err := cmd.CombinedOutput()
	_ = os.WriteFile(filepath.Join(env.logDir, strings.ReplaceAll(name, " ", "-")+".log"), out, 0o644)
	if err != nil {
		t.Fatalf("%s: %v\n%s", name, err, out)
	}
}

func withConfig(config map[string]string) []string {
	out := hermetic()
	for key, value := range config {
		out = append(out, key+"="+value)
	}
	return out
}

func tail(path string, lines int) string {
	file, err := os.Open(path)
	if err != nil {
		return "(unreadable: " + err.Error() + ")"
	}
	defer func() { _ = file.Close() }()
	var ring []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		ring = append(ring, scanner.Text())
		if len(ring) > lines {
			ring = ring[1:]
		}
	}
	return strings.Join(ring, "\n")
}

func requirePortFree(t *testing.T, address, owner string) {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("%s is in use, and %s needs it: %v\n"+
			"Most likely a development copy is still running. Stop it; the proof will not share a port "+
			"with a process it did not start.", address, owner, err)
	}
	_ = listener.Close()
}

func waitHTTP(t *testing.T, target string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	var last string
	for time.Now().Before(deadline) {
		response, err := http.Get(target)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
			last = response.Status
		} else {
			last = err.Error()
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("%s did not answer 200 within %s; last: %s", target, within, last)
}

// ---------------------------------------------------------------------------------------------
// The poison proxy
// ---------------------------------------------------------------------------------------------

type poisonProxy struct {
	server   *httptest.Server
	poison   atomic.Bool
	rejected atomic.Int64

	// down answers 503, the consumer being out of service. The publisher classifies it
	// unavailable, and a priority row is retried and released, never dead-lettered.
	down        atomic.Bool
	unavailable atomic.Int64

	// stall holds the delivery past the dispatcher's publish timeout and never forwards it: a
	// timeout before the consumer could commit anything.
	stall   atomic.Bool
	stalled atomic.Int64

	// flaky answers 503 to the first delivery of each event and forwards every later one: one failed
	// attempt per event, the failing path's latency.
	flaky    atomic.Bool
	flakedMu sync.Mutex
	flaked   map[string]bool
}

func newPoisonProxy(t *testing.T, target string) *poisonProxy {
	t.Helper()
	upstream, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parsing the consumer address: %v", err)
	}
	forward := httputil.NewSingleHostReverseProxy(upstream)

	p := &poisonProxy{flaked: map[string]bool{}}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.poison.Load() {
			_, _ = io.Copy(io.Discard, r.Body)
			p.rejected.Add(1)
			w.Header().Set("Content-Type", "application/json")
			// 422: one of the three statuses the publisher classifies as poison. The body says who
			// refused, so a reader of the dead letter's failure_detail is not sent to look at the
			// consumer.
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = io.WriteString(w, `{"error":"refused by the system-proof proxy to create a security dead letter"}`)
			return
		}
		if p.down.Load() {
			_, _ = io.Copy(io.Discard, r.Body)
			p.unavailable.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if p.flaky.Load() {
			body, _ := io.ReadAll(r.Body)
			var envelope struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(body, &envelope)
			p.flakedMu.Lock()
			first := !p.flaked[envelope.ID]
			p.flaked[envelope.ID] = true
			p.flakedMu.Unlock()
			if first {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
		}
		if p.stall.Load() {
			_, _ = io.Copy(io.Discard, r.Body)
			p.stalled.Add(1)
			// Held until the dispatcher gives up on it, which it does at its publish timeout. The
			// consumer never sees this request, so nothing can have been committed.
			select {
			case <-r.Context().Done():
			case <-time.After(3 * publishTimeout):
			}
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
		forward.ServeHTTP(w, r)
	}))
	t.Cleanup(p.server.Close)
	return p
}

func (p *poisonProxy) url() string { return p.server.URL }

// ---------------------------------------------------------------------------------------------
// The two APIs
// ---------------------------------------------------------------------------------------------

type client struct {
	t    *testing.T
	http *http.Client
}

func producerURL(path string) string { return "http://" + producerAddress + path }

func (c *client) token(query string) string {
	c.t.Helper()
	response, err := c.http.Get(issuerURL + "/token?" + query)
	if err != nil {
		c.t.Fatalf("minting a token (%s): %v", query, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		c.t.Fatalf("minting a token (%s): %s %s", query, response.Status, body)
	}
	return strings.TrimSpace(string(body))
}

func (c *client) do(method, target, token string, body any) (int, map[string]any) {
	c.t.Helper()

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			c.t.Fatalf("encoding a request body: %v", err)
		}
		reader = strings.NewReader(string(encoded))
	}
	request, err := http.NewRequest(method, target, reader)
	if err != nil {
		c.t.Fatalf("building %s %s: %v", method, target, err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	// Every provider-scoped call writes an access record and is refused without a reason. Sent on
	// every call rather than only on provider ones, because the header is harmless elsewhere and a
	// forgotten one would present as a 400 from a service that is working.
	request.Header.Set("X-Administrative-Reason", "system proof: Proof A across the process boundary")

	response, err := c.http.Do(request)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, target, err)
	}
	defer func() { _ = response.Body.Close() }()

	raw, _ := io.ReadAll(response.Body)
	decoded := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &decoded)
	}
	if len(decoded) == 0 && len(raw) > 0 {
		decoded["_raw"] = string(raw)
	}
	return response.StatusCode, decoded
}

func (c *client) expect(status int, method, target, token string, body any) map[string]any {
	c.t.Helper()
	got, decoded := c.do(method, target, token, body)
	if got != status {
		c.t.Fatalf("%s %s answered %d, want %d: %v", method, target, got, status, decoded)
	}
	return decoded
}

type principal struct {
	principal  string
	membership string
	version    int64  // the membership_version the grant returned, which a transition must name
	operate    string // a token whose subject is this principal, for the consumer's operations
}

func grant(c *client, tenantToken string) principal {
	c.t.Helper()
	minted, err := id.NewV7()
	if err != nil {
		c.t.Fatalf("minting a principal: %v", err)
	}
	result := c.expect(http.StatusCreated, http.MethodPost, producerURL("/v1/memberships"), tenantToken,
		map[string]any{
			"principal_id": minted.String(),
			"subject_type": "human",
			"provenance":   "system-proof",
			"valid_from":   time.Now().UTC().Add(-time.Minute).Format(time.RFC3339),
		})
	view, _ := result["membership"].(map[string]any)
	membershipID, _ := view["membership_id"].(string)
	if membershipID == "" {
		c.t.Fatalf("the grant returned no membership identifier: %v", result)
	}
	version, _ := view["version"].(float64)
	if version < 1 {
		c.t.Fatalf("the grant returned no membership version: %v", result)
	}
	return principal{
		principal:  minted.String(),
		membership: membershipID,
		version:    int64(version),
		operate:    c.token("role=operate&subject=" + minted.String()),
	}
}

// revoke withdraws a principal's Membership at the version its grant returned. organization-control
// requires the version on every Membership transition and a reason on a revocation
// (TDD-organization-control-002 1.9.0 §API); the reason travels on every call (see do). Each
// principal here is revoked straight after its grant, so that version is the stored one.
func revoke(c *client, tenantToken string, p principal) {
	c.t.Helper()
	c.expect(http.StatusOK, http.MethodPost, producerURL("/v1/memberships/"+p.membership+"/revoke"), tenantToken,
		map[string]any{"expected_version": p.version})
}

type decision struct {
	Status  int
	Allowed bool
	Reason  string
	Stale   bool
}

func (d decision) String() string {
	verdict := "DENIED"
	if d.Allowed {
		verdict = "ALLOWED"
	}
	return fmt.Sprintf("%s (%d) stale=%v %q", verdict, d.Status, d.Stale, d.Reason)
}

// decide asks the consumer, over HTTP, as the principal, for a LOW_RISK operation.
func decide(t *testing.T, c *client, who principal) decision {
	t.Helper()
	status, body := c.do(http.MethodGet, "http://"+consumerAddress+"/v1/directory/"+tenantID, who.operate, nil)
	allowedField, _ := body["allowed"].(bool)
	reason, _ := body["reason"].(string)
	stale, _ := body["stale"].(bool)
	return decision{Status: status, Allowed: allowedField && status == http.StatusOK, Reason: reason, Stale: stale}
}

func allowed(d decision) bool { return d.Allowed }

func refusedForDebt(d decision) bool { return !d.Allowed && isDebtReason(d.Reason) }

// The two reasons, matched on the phrase each enforcement branch owns in
// internal/httpapi/enforce.go. Loose on purpose: the proof is about which branch answered, not
// about the wording around it.
func isDebtReason(reason string) bool { return strings.Contains(reason, "given up on") }

func isWithdrawalReason(reason string) bool { return strings.Contains(reason, "no active membership") }

// versionOf reads a Tenant's version from either shape the producer answers with: the Tenant itself,
// or a transition result carrying it under "tenant".
func versionOf(t *testing.T, body map[string]any) int64 {
	t.Helper()
	if nested, ok := body["tenant"].(map[string]any); ok {
		body = nested
	}
	version, ok := body["version"].(float64)
	if !ok || version <= 0 {
		t.Fatalf("the producer's tenant carries no version: %v", body)
	}
	return int64(version)
}

func refusedForTenant(d decision) bool {
	return !d.Allowed && strings.Contains(d.Reason, "tenant is not active")
}

// waitDecision polls until the predicate holds or the bound passes, and fails with the last
// answer. The bound is the assertion: a decision that arrives later than it is a failure, not a
// slow pass.
func waitDecision(t *testing.T, c *client, who principal, within time.Duration, what string,
	want func(decision) bool) decision {
	t.Helper()
	deadline := time.Now().Add(within)
	var last decision
	for {
		last = decide(t, c, who)
		if want(last) {
			return last
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited %s for %s; last answer: %s", within, what, last)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

type frontierFacts struct {
	Unpublished          bool  `json:"unpublished"`
	SecurityDebt         bool  `json:"security_debt"`
	SecurityDeadLettered int64 `json:"security_dead_lettered"`
}

func waitFrontier(t *testing.T, c *client, providerToken, what string, want func(frontierFacts) bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var last map[string]any
	for time.Now().Before(deadline) {
		status, body := c.do(http.MethodGet, producerURL("/v1/projections/frontier"), providerToken, nil)
		last = body
		if status == http.StatusOK {
			encoded, _ := json.Marshal(body)
			var facts frontierFacts
			if err := json.Unmarshal(encoded, &facts); err == nil && want(facts) {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("waited 30s for %s; last frontier: %v", what, last)
}

// ---------------------------------------------------------------------------------------------
// Observing the producer's database
// ---------------------------------------------------------------------------------------------
//
// Read-only, as the owner, and only for facts an operator would read off the incident: which event
// is dead-lettered, and whether a receipt exists. Nothing here writes, so nothing here can make the
// chain succeed.

func openProducer(t *testing.T, env environment) *fdb.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := fdb.Open(ctx, fdb.Config{
		Name:     "systemproof-observer",
		DSN:      withCredentials(withDatabase(env.adminDSN, producerDatabase), producerOwner, producerOwnerPassword),
		MaxConns: 2,
	})
	if err != nil {
		t.Fatalf("opening the producer database for observation: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

type deadLetter struct {
	eventID      string
	failureClass string
	priority     int16
	consumer     string
}

// Aggregates rather than a row that may be absent: they always return one row, so "not yet" is a
// count of zero instead of a driver-specific no-rows error this package would have to import the
// driver to recognise.
func waitDeadLetter(t *testing.T, pool *fdb.Pool, membershipID string) deadLetter {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var (
			letter deadLetter
			count  int
		)
		err := pool.InTx(context.Background(), func(ctx context.Context, tx fdb.Tx) error {
			return tx.QueryRow(ctx, `
				SELECT count(*),
				       coalesce(max(event_id::text), ''),
				       coalesce(max(failure_class), ''),
				       coalesce(max(priority), -1),
				       coalesce(max(consumer), '')
				  FROM platform.dead_letter
				 WHERE resolved_at IS NULL
				   AND event_type = $1
				   AND payload->>'membership_id' = $2`, revokedType, membershipID,
			).Scan(&count, &letter.eventID, &letter.failureClass, &letter.priority, &letter.consumer)
		})
		if err != nil {
			t.Fatalf("reading platform.dead_letter: %v", err)
		}
		switch {
		case count == 1:
			return letter
		case count > 1:
			t.Fatalf("%d unresolved dead letters for A's revocation; the proof expects exactly one", count)
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("A's revocation (membership %s) was not dead-lettered within 30s", membershipID)
	return deadLetter{}
}

// waitReceipt waits for the replay to be DELIVERED -- a receipt under any consumer name -- and
// deliberately does not judge it.
//
// Whether the receipt is evidence is the resolver's decision, and the proof has to let the resolver
// make it. A first version filtered by consumer name here, and a dispatcher configured with the
// wrong name then failed the proof in this observer, before the resolver was ever asked: red for the
// right situation and the wrong reason. The claim under test is that the SYSTEM refuses to close an
// incident on a receipt nobody's resolution reads, so the refusal has to come from the system.
func waitReceipt(t *testing.T, pool *fdb.Pool, eventID string) (consumer, evidence string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		err := pool.InTx(context.Background(), func(ctx context.Context, tx fdb.Tx) error {
			return tx.QueryRow(ctx, `
				SELECT coalesce(max(consumer), ''), coalesce(max(evidence), '')
				  FROM platform.delivery_receipt WHERE event_id = $1::uuid`, eventID).Scan(&consumer, &evidence)
		})
		if err != nil {
			t.Fatalf("reading platform.delivery_receipt: %v", err)
		}
		if consumer != "" {
			return consumer, evidence
		}
		time.Sleep(250 * time.Millisecond)
	}
	// Not fatal, for the same reason: the resolver is asked next, and "nothing acknowledged this
	// event" is its refusal to give, not this observer's.
	t.Logf("no delivery receipt for %s within 30s: the replay did not reach the consumer", eventID)
	return "", ""
}

// ---------------------------------------------------------------------------------------------
// The closure artifact
// ---------------------------------------------------------------------------------------------

type timeline struct {
	t       *testing.T
	started time.Time
	mu      sync.Mutex
	entries []string
}

func newTimeline(t *testing.T) *timeline {
	return &timeline{t: t, started: time.Now()}
}

func (l *timeline) mark(format string, args ...any) {
	entry := fmt.Sprintf("%8s  %s", time.Since(l.started).Round(time.Millisecond), fmt.Sprintf(format, args...))
	l.mu.Lock()
	l.entries = append(l.entries, entry)
	l.mu.Unlock()
	l.t.Log(entry)
}

// writeSummary records what was proven and against what. Written whether the run passed or failed:
// a failed closure run with no record of its revisions cannot be inspected.
func writeSummary(t *testing.T, env environment, r revisions, l *timeline) {
	verdict := "PASSED"
	if t.Failed() {
		verdict = "FAILED"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "## Proof A across the process boundary: %s\n\n", verdict)
	fmt.Fprintf(&b, "| Component | Revision |\n| :-- | :-- |\n")
	fmt.Fprintf(&b, "| organization-control | `%s` |\n", r.producerCommit)
	dirty := ""
	if r.consumerDirty {
		dirty = " (dirty -- not a closure run)"
	}
	fmt.Fprintf(&b, "| foundation-reference | `%s`%s |\n", r.consumerCommit, dirty)
	fmt.Fprintf(&b, "| foundation-platform (producer) | `%s` |\n", r.producerPlatform)
	fmt.Fprintf(&b, "| foundation-platform (consumer) | `%s` |\n\n", r.consumerPlatform)
	fmt.Fprintf(&b, "Frontier cache interval `%s`, propagation bound `%s`.\n\n", frontierTTL(), frontierTTL()+slack)
	b.WriteString("```text\n")
	l.mu.Lock()
	for _, entry := range l.entries {
		b.WriteString(entry + "\n")
	}
	l.mu.Unlock()
	b.WriteString("```\n")

	_ = os.WriteFile(filepath.Join(env.logDir, "summary.md"), []byte(b.String()), 0o644)
	if path := os.Getenv("GITHUB_STEP_SUMMARY"); path != "" {
		if file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			_, _ = file.WriteString(b.String())
			_ = file.Close()
		}
	}
	t.Logf("summary written to %s", filepath.Join(env.logDir, "summary.md"))
}
