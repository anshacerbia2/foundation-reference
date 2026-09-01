package httpapi

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/anshacerbia2/foundation-platform/id"

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

// Enforcer answers whether one operation may proceed, given its class.
type Enforcer struct {
	projector Projection
	authority Authority
	maxAge    time.Duration
}

func NewEnforcer(projector Projection, authority Authority, maxAge time.Duration) (*Enforcer, error) {
	if projector == nil {
		return nil, ErrNoProjector
	}
	if maxAge <= 0 {
		return nil, errors.New("httpapi: maxAge must be positive")
	}
	// authority may be nil, and that is a deliberate configuration rather than a defect:
	// a deployment with no authority configured can still serve LOW_RISK traffic. The two
	// classes that need it are refused, which is the correct answer to "I cannot check".
	return &Enforcer{projector: projector, authority: authority, maxAge: maxAge}, nil
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

	// >= rather than > when the budget is zero, so a class declaring zero tolerance treats any
	// projection as stale. With >, a budget of zero would admit an age of zero — which is only
	// ever true of a projection that just applied something, so the class would pass or fail on
	// whether an unrelated event happened to land in the same instant.
	stale := ageErr != nil || age > policy.MaxStale || policy.MaxStale == 0

	record, err := e.projector.Lookup(ctx, tenantID, principalID)
	switch {
	case err == nil && record.Active():
		// Positive authority, present rather than inferred. This is the answer that was impossible
		// while the projection held only revocations: absence had to mean permission, so "allowed"
		// meant "no bad news has arrived".
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
				Reason: e.staleReason(ageErr, age, policy.MaxStale) + ", and this class fails open",
				Stale:  true,
				Age:    age,
			}, nil
		}
		return Decision{
			Allow:  false,
			Reason: e.staleReason(ageErr, age, policy.MaxStale) + ", and this class fails closed",
			Stale:  true,
			Age:    age,
		}, nil

	case err == nil:
		// A revocation that has been applied is enforced regardless of class or freshness.
		// This is the property Proof A exists to demonstrate.
		// Projected and not active: suspended or revoked. Refused regardless of class and regardless
		// of freshness, because a withdrawal that has arrived is not made less true by being old.
		// This is the property Proof A exists to demonstrate.
		return Decision{
			Allow:  false,
			Reason: fmt.Sprintf("membership is %s at version %d", record.Status, record.Version),
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

func (e *Enforcer) staleReason(ageErr error, age, budget time.Duration) string {
	if ageErr != nil {
		return "the projection's freshness is unknown"
	}
	if budget == 0 {
		return "this class tolerates no staleness, and a projection is not an authoritative answer"
	}
	return fmt.Sprintf("the projection is %s old, past this class's %s bound",
		age.Round(time.Millisecond), budget)
}
