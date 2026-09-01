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
	return e.decideFromProjection(ctx, policy, tenantID, principalID)
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
	stale := ageErr != nil || age > e.maxAge

	record, err := e.projector.Lookup(ctx, tenantID, principalID)
	switch {
	case err == nil && record.Revoked:
		// A revocation that has been applied is enforced regardless of class or freshness.
		// This is the property Proof A exists to demonstrate.
		return Decision{
			Allow:  false,
			Reason: fmt.Sprintf("membership revoked at version %d", record.Version),
			Stale:  stale,
			Age:    age,
		}, nil

	case errors.Is(err, projection.ErrNotProjected):
		// Never seen. Absence of a revocation is not proof of validity: it is either a
		// membership that was never revoked, or one whose revocation has not arrived.
		// Only freshness tells those apart, and only the class decides what to do about it.
		if !stale {
			return Decision{
				Allow:  true,
				Reason: fmt.Sprintf("no revocation applied, projection is %s old", age.Round(time.Millisecond)),
				Age:    age,
			}, nil
		}
		if policy.FailOpen {
			return Decision{
				Allow:  true,
				Reason: e.staleReason(ageErr, age) + ", and this class fails open",
				Stale:  true,
				Age:    age,
			}, nil
		}
		return Decision{
			Allow:  false,
			Reason: e.staleReason(ageErr, age) + ", and this class fails closed",
			Stale:  true,
			Age:    age,
		}, nil

	case errors.Is(err, projection.ErrProjectionCold):
		return Decision{Allow: policy.FailOpen, Reason: "the projection has applied nothing yet", Stale: true}, nil

	default:
		// The read itself broke. This is never fail-open eligible, whatever the class:
		// fail-open exists for a projection that is merely behind, not for one that cannot
		// be read at all.
		return Decision{Allow: false, Reason: "the projection could not be read"}, err
	}
}

func (e *Enforcer) staleReason(ageErr error, age time.Duration) string {
	if ageErr != nil {
		return "the projection's freshness is unknown"
	}
	return fmt.Sprintf("the projection is %s old, past the %s bound",
		age.Round(time.Millisecond), e.maxAge)
}
