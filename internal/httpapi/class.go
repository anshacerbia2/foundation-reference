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
// test can assert it, and so a new class cannot be added without stating all four answers.
type Policy struct {
	// FailOpen decides what happens when the projection is unavailable or too old.
	FailOpen bool

	// UsesProjection is false for the classes that must reach the authority. When false,
	// MaxAge is meaningless and an unreachable authority is a refusal.
	UsesProjection bool

	// AuditEveryAccess distinguishes the classes where each access is recorded from those
	// where an aggregate is enough.
	AuditEveryAccess bool
}

// policies is the whole table, in one place, because a policy spread across handlers is a
// policy nobody can read. Adding a class without adding a row here fails at startup.
var policies = map[Class]Policy{
	LowRisk:             {FailOpen: true, UsesProjection: true, AuditEveryAccess: false},
	HighConfidentiality: {FailOpen: false, UsesProjection: true, AuditEveryAccess: true},
	Privileged:          {FailOpen: false, UsesProjection: false, AuditEveryAccess: true},
	Irreversible:        {FailOpen: false, UsesProjection: false, AuditEveryAccess: true},
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

	// Stale records that the answer came from a projection older than the bound. It is
	// reported on both outcomes, because an allow-while-stale is the event worth alerting
	// on even though the request succeeded.
	Stale bool

	Age time.Duration
}
