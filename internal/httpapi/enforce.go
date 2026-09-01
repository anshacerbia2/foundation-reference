package httpapi

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/foundation-reference/internal/frontier"
	"github.com/anshacerbia2/foundation-reference/internal/projection"
)

var ErrNoProjector = errors.New("httpapi: a projector is required")

// Projection is the narrow view the enforcer needs, declared here rather than beside the
// implementation.
//
// It is an interface for a reason a test can point at: the branch where the read itself
// fails is the one that must never fail open, and it cannot be produced against a healthy
// database. With a concrete dependency that branch would be reachable only by breaking the
// database, so it would go untested — which is exactly the branch where an untested
// fail-open admits a revoked caller.
type Projection interface {
	Age(ctx context.Context) (time.Duration, error)
	Lookup(ctx context.Context, tenantID, principalID id.UUID) (projection.Record, error)
}

// Frontier is the producer's publication state, which the consumer cannot derive for itself.
//
// An interface so the enforcer can be tested against a producer that owes an old delivery without one
// existing -- the branch that matters most here is the one where the producer is behind, and provoking
// that against a real outbox means arranging a stuck dispatcher.
type Frontier interface {
	Frontier(ctx context.Context) (frontier.Facts, error)
}

// Enforcer answers whether one operation may proceed, given its class.
type Enforcer struct {
	projector Projection
	authority Authority
	frontier  Frontier
	maxAge    time.Duration
	now       func() time.Time
}

func NewEnforcer(projector Projection, authority Authority, publication Frontier, maxAge time.Duration) (*Enforcer, error) {
	if projector == nil {
		return nil, ErrNoProjector
	}
	if maxAge <= 0 {
		return nil, errors.New("httpapi: maxAge must be positive")
	}
	// authority may be nil, and that is a deliberate configuration rather than a defect:
	// a deployment with no authority configured can still serve LOW_RISK traffic. The two
	// classes that need it are refused, which is the correct answer to "I cannot check".
	// A nil frontier is a deployment that cannot ask the producer how far behind it is. Permitted,
	// and it costs every projection-backed class its window: without the producer's facts the only
	// honest answer about gaps is that they are unknown. See freshness below.
	return &Enforcer{
		projector: projector,
		authority: authority,
		frontier:  publication,
		maxAge:    maxAge,
		now:       time.Now,
	}, nil
}

// Decide is the single place this consumer turns a class plus a projection state into an
// answer. Every route goes through it, so there is no handler that quietly reads the
// projection directly.
func (e *Enforcer) Decide(ctx context.Context, class Class, tenantID, principalID id.UUID) (Decision, error) {
	policy, err := PolicyFor(class)
	if err != nil {
		return Decision{}, err
	}

	if !policy.UsesProjection {
		return e.decideFromAuthority(ctx, class, tenantID, principalID)
	}
	// The budget comes from the class, with the configured window applied only to the class that
	// declares one. Reading e.maxAge here directly is what let HIGH_CONFIDENTIALITY inherit
	// LOW_RISK's sixty seconds while declaring zero tolerance.
	return e.decideFromProjection(ctx, policy.FromConfig(e.maxAge), tenantID, principalID)
}

func (e *Enforcer) decideFromAuthority(ctx context.Context, class Class, tenantID, principalID id.UUID) (Decision, error) {
	if e.authority == nil {
		return Decision{
			Allow:  false,
			Reason: fmt.Sprintf("%s requires the authority and none is configured", class),
		}, nil
	}

	verdict, err := e.authority.Verify(ctx, tenantID, principalID)
	if err != nil {
		// Unreachable authority is a refusal, not a fallback to the projection. Falling back
		// would make the classes that exist to avoid the replica depend on it exactly when the
		// estate is degraded.
		return Decision{
			Allow:  false,
			Reason: fmt.Sprintf("the authority could not be reached: %v", err),
		}, nil
	}
	if !verdict.Granted {
		return Decision{Allow: false, Reason: "the authority does not grant this context"}, nil
	}
	return Decision{
		Allow: true,
		Reason: fmt.Sprintf("granted by the authority at membership version %d, tenant security version %d",
			verdict.MembershipVersion, verdict.TenantSecurityVersion),
	}, nil
}

func (e *Enforcer) decideFromProjection(ctx context.Context, policy Policy, tenantID, principalID id.UUID) (Decision, error) {
	age, ageErr := e.projector.Age(ctx)

	// A consumer that never took a snapshot holds a model containing everything that happened since
	// it connected and nothing that happened before, so it holds no positive authority for anyone.
	// Refused for every class, ahead of any freshness question: this is the one invariant on this
	// side that is sound rather than a hint.
	if errors.Is(ageErr, projection.ErrNotBootstrapped) {
		return Decision{
			Allow:  false,
			Reason: "this consumer has taken no snapshot, so it holds no projected authority",
			Stale:  true,
		}, nil
	}

	stale, staleBecause := e.stale(ctx, policy, age, ageErr)

	record, err := e.projector.Lookup(ctx, tenantID, principalID)
	switch {
	case err == nil:
		// An active membership exists for this pair — positive authority, present rather than
		// inferred. Lookup answers EXISTS-active rather than returning a row to inspect, because the
		// authority permits several memberships per pair and only one of them needs to be active.
		//
		// This is the answer that was impossible while the projection held only revocations, where
		// absence had to mean permission and "allowed" meant "no bad news has arrived".
		//
		// Freshness still decides whether the answer may be used, because an active row can be one
		// the revocation has not reached yet.
		if !stale {
			return Decision{
				Allow:  true,
				Reason: fmt.Sprintf("membership active at version %d", record.Version),
				Age:    age,
			}, nil
		}
		if policy.FailOpen {
			return Decision{
				Allow:  true,
				Reason: staleBecause + ", and this class fails open",
				Stale:  true,
				Age:    age,
			}, nil
		}
		return Decision{
			Allow:  false,
			Reason: staleBecause + ", and this class fails closed",
			Stale:  true,
			Age:    age,
		}, nil

	case errors.Is(err, projection.ErrWithdrawn):
		// Rows exist for this pair and none of them is active: every membership this principal held
		// in this tenant is suspended or revoked. Refused regardless of class and regardless of
		// freshness, because a withdrawal that has arrived is not made less true by being old. This
		// is the property Proof A exists to demonstrate.
		//
		// Kept apart from ErrNotProjected below, which also refuses: an operator reading a refusal
		// needs to know whether this consumer has ever seen the principal at all.
		return Decision{
			Allow:  false,
			Reason: "this principal holds no active membership in this tenant",
			Stale:  stale,
			Age:    age,
		}, nil

	case errors.Is(err, projection.ErrNotProjected):
		// No positive authority is projected for this pair, so there is nothing to permit. Refused
		// for every class, and freshness does not enter into it: fail-open exists for an answer that
		// might be out of date, not for the absence of an answer.
		//
		// This is the correction the principal review's first P0 demanded. Before, an absent row was
		// indistinguishable between "holds an active membership" and "was never a member", and the
		// consumer permitted both.
		return Decision{
			Allow:  false,
			Reason: "no membership is projected for this principal in this tenant",
			Stale:  stale,
			Age:    age,
		}, nil

	default:
		// The read itself broke. This is never fail-open eligible, whatever the class:
		// fail-open exists for a projection that is merely behind, not for one that cannot
		// be read at all.
		return Decision{Allow: false, Reason: "the projection could not be read"}, err
	}
}

// stale composes the three things freshness depends on, and returns why.
//
// Two of the three are local hints and only one is sound about gaps:
//
//   - the consumer's own apply age, which answers "when did the last event land" and cannot see a
//     delivery that never arrived;
//   - the producer's oldest owed delivery, which is the only term that can, because a rolled-back
//     sequence number was never in its outbox;
//   - whether the producer could be reached at all, which is unknown rather than fine.
//
// Composed here rather than in the producer deliberately: the producer cannot see which operation is
// being authorised, and the same lag is acceptable for a directory read and unacceptable for a
// payroll one.
func (e *Enforcer) stale(ctx context.Context, policy Policy, age time.Duration, ageErr error) (bool, string) {
	if policy.MaxStale == 0 {
		// A class tolerating nothing does not need a measurement to refuse. Stated first so the
		// network call below is not made for an answer that cannot change.
		return true, "this class tolerates no staleness, and a projection is not an authoritative answer"
	}
	if ageErr != nil {
		return true, "the projection's freshness is unknown"
	}
	if age > policy.MaxStale {
		return true, fmt.Sprintf("the projection is %s old, past this class's %s bound",
			age.Round(time.Millisecond), policy.MaxStale)
	}

	if e.frontier == nil {
		// No producer facts configured, so gaps are unknowable. The consumer's own age cannot rule
		// out a delivery that never arrived, so the honest answer is stale -- and the class decides
		// what that costs. Reporting fresh here would be the original defect with extra steps: a
		// consumer certifying itself current from information that cannot show it is not.
		return true, "no publication frontier is configured, so an undelivered event cannot be ruled out"
	}

	facts, err := e.frontier.Frontier(ctx)
	if err != nil {
		return true, fmt.Sprintf("the publication frontier could not be read: %v", err)
	}
	if !facts.Unpublished {
		return false, ""
	}

	// The producer observed its oldest owed delivery at an instant that has since passed, so the age
	// it reported has grown by the time since. Ignoring that would let a cached answer certify
	// freshness it can no longer support.
	owed := facts.OldestUnpublishedAge + e.now().UTC().Sub(facts.ObservedAt)
	if owed > policy.MaxStale {
		return true, fmt.Sprintf("the producer has owed a delivery for %s, past this class's %s bound",
			owed.Round(time.Millisecond), policy.MaxStale)
	}
	return false, ""
}
