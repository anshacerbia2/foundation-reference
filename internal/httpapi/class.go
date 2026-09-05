package httpapi

import (
	"errors"
	"fmt"
	"time"
)

// Class is the security class of an operation, and it is what decides how this consumer
// behaves when its projection cannot answer.
//
// The class is a property of the operation, not of the HTTP method. `GET /payroll` and
// `GET /passport` are reads with higher confidentiality impact than most writes, so a
// policy keyed on read-versus-write is wrong exactly where being wrong is most expensive.
type Class string

const (
	// LowRisk may be served from a projection that is younger than the configured bound.
	// Past the bound it is refused: a fail-open with no age limit is a revocation that
	// silently never applies.
	LowRisk Class = "LOW_RISK"

	// HighConfidentiality is refused whenever the projection cannot be confirmed current.
	// The data is disclosed once and cannot be recalled, so availability does not outrank
	// the possibility that the membership was revoked a moment ago.
	HighConfidentiality Class = "HIGH_CONFIDENTIALITY"

	// Privileged does not consult the projection at all. It asks the authority.
	Privileged Class = "PRIVILEGED"

	// Irreversible does not consult the projection at all, for the same reason as
	// Privileged with less room for argument: an effect that cannot be undone must not be
	// authorised by a replica that is permitted to lag.
	Irreversible Class = "IRREVERSIBLE"
)

var ErrUnknownClass = errors.New("httpapi: operation has no security class")

// Policy is the behaviour a class commits to. It is a value rather than a document so a
// test can assert it, and so a new class cannot be added without stating every answer.
//
// # There is no FailOpen field, and its removal is the point
//
// There was one, set on LOW_RISK alone, and it did what its name says: past the bound, a stale
// active row was served anyway with the answer marked stale. The principal review named the
// consequence and it is not arguable — a revocation that arrives late is refused for as long as the
// window, and then permitted forever. The marker made it visible and changed nothing about the
// access, so the enforcement bound was decoration on the one path where lag actually happens.
//
// What is left is one axis rather than two: MaxStale is the whole permission. A positive budget means
// this class may answer from the projection while it is inside the budget, and zero means it may not
// answer from the projection at all. Past the budget every class refuses, so "bounded" is now a
// property of the code rather than a claim about it, and the two-field arrangement that let a bound
// and a behaviour disagree is gone with it.
type Policy struct {
	// UsesProjection is false for the classes that must reach the authority. When false,
	// MaxAge is meaningless and an unreachable authority is a refusal.
	UsesProjection bool

	// AuditEveryAccess distinguishes the classes where each access is recorded from those
	// where an aggregate is enough.
	AuditEveryAccess bool

	// Behavior is the estate's own name for what this class does with a stale projection.
	//
	// organization-control's consumer registry already declares three: use_with_marker,
	// revalidate, and fail_closed. Naming them here keeps one vocabulary across the estate -- a
	// second set of words for the same three behaviours is how a registered consumer ends up
	// described one way in the registry and behaving another.
	//
	// use_with_marker now means what its name always said and its implementation did not: an answer
	// served from the projection carries a freshness marker, and past the bound it is refused. It
	// never meant "serve it anyway with a label attached".
	//
	// The registry holds one value per consumer while enforcement here is per operation class, so
	// the two cannot correspond exactly. That mismatch is a contract question rather than a bug in
	// either place, and TestBehaviourAgreesWithTheFailurePolicy keeps the two fields from drifting
	// in the meantime.
	Behavior string

	// MaxStale is this class's own freshness budget, and zero means zero tolerance.
	//
	// One global window for every projection-backed class was wrong, and the principal review
	// named it: HIGH_CONFIDENTIALITY declared fail_closed and then inherited LOW_RISK's sixty
	// seconds, so a thirty-second-old projection with no recorded revocation served confidential
	// data. A class that declares zero stale tolerance and reads a window from configuration is a
	// class whose declaration is decoration.
	//
	// LOW_RISK is the only class that takes the configured value; the others carry their own, and
	// the enforcer reads the policy rather than the configuration.
	//
	// With FailOpen gone this field is the whole of the projection permission: positive means the
	// class may answer from the projection inside the budget, zero means it may not answer from the
	// projection at all, and past the budget every class refuses.
	MaxStale time.Duration
}

// ServesFromProjection reports whether this class may answer from the projection at all.
//
// Derived rather than stored. It replaces FailOpen, which was stored, and the difference is that a
// stored flag could contradict the budget beside it -- which is how HIGH_CONFIDENTIALITY came to
// declare fail_closed while inheriting LOW_RISK's sixty seconds. A derived answer cannot disagree
// with what it is derived from.
func (p Policy) ServesFromProjection() bool {
	return p.UsesProjection && p.MaxStale > 0
}

// FromConfig returns the policy with the deployment's window applied to the one class that has
// one. Every other class keeps the budget it declares.
func (p Policy) FromConfig(configured time.Duration) Policy {
	if p.Behavior == UseWithMarker {
		p.MaxStale = configured
	}
	return p
}

// The three behaviours organization-control's registry declares.
const (
	UseWithMarker = "use_with_marker"
	Revalidate    = "revalidate"
	FailClosed    = "fail_closed"
)

// policies is the whole table, in one place, because a policy spread across handlers is a
// policy nobody can read. Adding a class without adding a row here fails at startup.
var policies = map[Class]Policy{
	// MaxStale on LOW_RISK is a placeholder replaced by FromConfig; the others are the budget.
	LowRisk:             {UsesProjection: true, AuditEveryAccess: false, Behavior: UseWithMarker, MaxStale: time.Minute},
	HighConfidentiality: {UsesProjection: true, AuditEveryAccess: true, Behavior: FailClosed, MaxStale: 0},
	Privileged:          {UsesProjection: false, AuditEveryAccess: true, Behavior: Revalidate},
	Irreversible:        {UsesProjection: false, AuditEveryAccess: true, Behavior: Revalidate},
}

func PolicyFor(class Class) (Policy, error) {
	policy, ok := policies[class]
	if !ok {
		return Policy{}, fmt.Errorf("%w: %q", ErrUnknownClass, class)
	}
	return policy, nil
}

// Classes lists every declared class. Tests use it to prove the table covers the constants,
// so a class added to one and not the other cannot pass review.
func Classes() []Class {
	return []Class{LowRisk, HighConfidentiality, Privileged, Irreversible}
}

// Decision is what an enforcement check concluded, and why. The reason is carried because
// "allowed" for two different reasons is two different operational facts: served from a
// fresh projection, versus served because the class permits a stale one.
type Decision struct {
	Allow  bool
	Reason string

	// Stale records that the answer came from a projection older than the bound, or from one whose
	// producer has given up on a delivery.
	//
	// It is now only ever reported alongside a refusal, since no class serves past its bound. Kept
	// as a field rather than folded into the reason string because the two facts are operationally
	// different: a refusal because the principal holds no membership is the system working, and a
	// refusal because this consumer cannot vouch for its own model is a degradation to alert on.
	Stale bool

	Age time.Duration
}
