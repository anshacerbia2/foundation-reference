package httpapi_test

import (
	"errors"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-reference/internal/httpapi"
)

// TestEveryOperationDeclaresAClass is the structural half of the policy.
//
// A route added without a class must not be servable at all. If the class were resolved by
// lookup with a default, the default would be wrong for some route — and the route most
// likely to be added in a hurry is the one most likely to need the strict answer.
func TestEveryOperationDeclaresAClass(t *testing.T) {
	operations := httpapi.Operations()
	if len(operations) == 0 {
		t.Fatal("no operations are declared, so this test proves nothing")
	}

	for _, operation := range operations {
		if operation.Class == "" {
			t.Errorf("%s %s declares no class", operation.Method, operation.Pattern)
			continue
		}
		if _, err := httpapi.PolicyFor(operation.Class); err != nil {
			t.Errorf("%s %s: %v", operation.Method, operation.Pattern, err)
		}
	}
}

// TestEveryClassIsReachableByHand keeps the surface honest as a demonstration: each of the
// four fail behaviours has a route somebody can call. A class with a policy and no route is
// a claim with no way to check it.
func TestEveryClassIsReachableByHand(t *testing.T) {
	covered := map[httpapi.Class]bool{}
	for _, operation := range httpapi.Operations() {
		covered[operation.Class] = true
	}
	for _, class := range httpapi.Classes() {
		if !covered[class] {
			t.Errorf("class %s has no route, so its behaviour cannot be exercised", class)
		}
	}
}

// TestThePolicyTableCoversEveryClass catches the other direction: a class constant added
// without a row in the table. Without this, PolicyFor would start returning an error at
// runtime for a class the code already refers to.
func TestThePolicyTableCoversEveryClass(t *testing.T) {
	for _, class := range httpapi.Classes() {
		if _, err := httpapi.PolicyFor(class); err != nil {
			t.Errorf("class %s has no policy: %v", class, err)
		}
	}
}

// TestOnlyLowRiskFailsOpen states the policy as an assertion rather than as prose.
//
// This is the test that fails if somebody widens fail-open, which is the change most likely
// to be made under delivery pressure and least likely to be noticed in review: it makes
// every symptom disappear.
func TestOnlyLowRiskFailsOpen(t *testing.T) {
	for _, class := range httpapi.Classes() {
		policy, err := httpapi.PolicyFor(class)
		if err != nil {
			t.Fatalf("PolicyFor(%s): %v", class, err)
		}
		if policy.FailOpen != (class == httpapi.LowRisk) {
			t.Errorf("%s: FailOpen = %v; only LOW_RISK may fail open", class, policy.FailOpen)
		}
	}
}

// TestThePrivilegedClassesDoNotUseTheProjection is the same discipline for the other axis.
func TestThePrivilegedClassesDoNotUseTheProjection(t *testing.T) {
	for _, class := range []httpapi.Class{httpapi.Privileged, httpapi.Irreversible} {
		policy, err := httpapi.PolicyFor(class)
		if err != nil {
			t.Fatalf("PolicyFor(%s): %v", class, err)
		}
		if policy.UsesProjection {
			t.Errorf("%s reads the projection; an operation that cannot be undone must not be authorised by a replica", class)
		}
		if !policy.AuditEveryAccess {
			t.Errorf("%s does not audit every access", class)
		}
	}
}

func TestAnUndeclaredClassIsAnError(t *testing.T) {
	if _, err := httpapi.PolicyFor(httpapi.Class("SOMEWHAT_SENSITIVE")); !errors.Is(err, httpapi.ErrUnknownClass) {
		t.Errorf("PolicyFor on an unknown class returned %v, want ErrUnknownClass", err)
	}
}

// TestBehaviourAgreesWithTheFailurePolicy keeps the estate's vocabulary and this package's booleans
// from drifting. Two fields describing one decision is a liability the moment they disagree: the
// registry would say one thing about a consumer and the code would do another, and only the code
// would be enforced.
func TestBehaviourAgreesWithTheFailurePolicy(t *testing.T) {
	for _, class := range httpapi.Classes() {
		policy, err := httpapi.PolicyFor(class)
		if err != nil {
			t.Fatalf("PolicyFor(%s): %v", class, err)
		}

		switch policy.Behavior {
		case httpapi.UseWithMarker:
			if !policy.FailOpen || !policy.UsesProjection {
				t.Errorf("%s is use_with_marker but does not serve from the projection", class)
			}
		case httpapi.FailClosed:
			if policy.FailOpen || !policy.UsesProjection {
				t.Errorf("%s is fail_closed but fails open or bypasses the projection", class)
			}
		case httpapi.Revalidate:
			if policy.UsesProjection {
				t.Errorf("%s is revalidate but reads the projection instead of the authority", class)
			}
			if policy.FailOpen {
				t.Errorf("%s is revalidate and fails open; an unrevalidated call must be refused", class)
			}
		default:
			t.Errorf("%s carries behaviour %q, which is not one the registry declares", class, policy.Behavior)
		}
	}
}

// TestOnlyTheMarkerClassCarriesAStalenessBudget states the rule that broke before: a class whose
// declared behaviour is fail_closed or revalidate must not have a window, because a window is
// permission to answer from a replica.
func TestOnlyTheMarkerClassCarriesAStalenessBudget(t *testing.T) {
	for _, class := range httpapi.Classes() {
		policy, err := httpapi.PolicyFor(class)
		if err != nil {
			t.Fatalf("PolicyFor(%s): %v", class, err)
		}

		applied := policy.FromConfig(90 * time.Second)
		switch class {
		case httpapi.LowRisk:
			if applied.MaxStale != 90*time.Second {
				t.Errorf("LOW_RISK ignored the configured window: %s", applied.MaxStale)
			}
		default:
			if applied.MaxStale != 0 {
				t.Errorf("%s took a %s staleness budget from configuration; only LOW_RISK may have one",
					class, applied.MaxStale)
			}
		}
	}
}
