package httpapi_test

// Every decision carries a code from the fixed set, and each branch its own. The refusal metric is
// labelled by code, so a branch with no code, or with another branch's, would count its refusals
// under the wrong reason.

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-reference/internal/frontier"
	"github.com/anshacerbia2/foundation-reference/internal/httpapi"
	"github.com/anshacerbia2/foundation-reference/internal/projection"
)

func TestEveryBranchDecidesWithItsOwnCode(t *testing.T) {
	active := projection.Record{Version: 1}
	debt := stubFrontier{facts: frontier.Facts{SecurityDebt: true, SecurityDeadLettered: 1,
		ObservedAt: time.Now().UTC(), ReadAt: time.Now().UTC()}}
	owed := stubFrontier{facts: frontier.Facts{Unpublished: true, OldestUnpublishedAge: time.Hour,
		ObservedAt: time.Now().UTC(), ReadAt: time.Now().UTC()}}

	for _, c := range []struct {
		name  string
		class httpapi.Class
		p     httpapi.Projection
		a     httpapi.Authority
		f     httpapi.Frontier
		want  string
	}{
		{"active and fresh", httpapi.LowRisk, stubProjection{age: time.Second, record: active}, nil, current(), httpapi.CodeActiveMembership},
		{"granted by the authority", httpapi.Privileged, stubProjection{}, stubAuthority{granted: true}, current(), httpapi.CodeAuthorityGranted},
		{"no authority configured", httpapi.Privileged, stubProjection{}, nil, current(), httpapi.CodeAuthorityUnconfigured},
		{"authority unreachable", httpapi.Privileged, stubProjection{}, stubAuthority{err: errors.New("down")}, current(), httpapi.CodeAuthorityUnreachable},
		{"authority refuses", httpapi.Privileged, stubProjection{}, stubAuthority{}, current(), httpapi.CodeAuthorityRefused},
		{"never bootstrapped", httpapi.LowRisk, stubProjection{ageErr: projection.ErrNotBootstrapped}, nil, current(), httpapi.CodeNotBootstrapped},
		{"withdrawn", httpapi.LowRisk, stubProjection{age: time.Second, lookupErr: projection.ErrWithdrawn}, nil, current(), httpapi.CodeWithdrawn},
		{"tenant inactive", httpapi.LowRisk, stubProjection{age: time.Second, lookupErr: projection.ErrTenantInactive}, nil, current(), httpapi.CodeTenantInactive},
		{"tenant not projected", httpapi.LowRisk, stubProjection{age: time.Second, lookupErr: projection.ErrTenantNotProjected}, nil, current(), httpapi.CodeTenantNotProjected},
		{"not projected", httpapi.LowRisk, stubProjection{age: time.Second, lookupErr: projection.ErrNotProjected}, nil, current(), httpapi.CodeNotProjected},
		{"read failed", httpapi.LowRisk, stubProjection{age: time.Second, lookupErr: errors.New("broken")}, nil, current(), httpapi.CodeReadFailed},
		{"zero tolerance", httpapi.HighConfidentiality, stubProjection{age: time.Second, record: active}, nil, current(), httpapi.CodeStaleZeroTolerance},
		{"unknown age", httpapi.LowRisk, stubProjection{ageErr: errors.New("no age"), record: active}, nil, current(), httpapi.CodeStaleUnknownAge},
		{"too old", httpapi.LowRisk, stubProjection{age: time.Hour, record: active}, nil, current(), httpapi.CodeStaleAge},
		{"no frontier", httpapi.LowRisk, stubProjection{age: time.Second, record: active}, nil, nil, httpapi.CodeStaleNoFrontier},
		{"frontier unreadable", httpapi.LowRisk, stubProjection{age: time.Second, record: active}, nil, stubFrontier{err: errors.New("down")}, httpapi.CodeStaleFrontierUnreadable},
		{"security debt", httpapi.LowRisk, stubProjection{age: time.Second, record: active}, nil, debt, httpapi.CodeStaleSecurityDebt},
		{"owed past the bound", httpapi.LowRisk, stubProjection{age: time.Second, record: active}, nil, owed, httpapi.CodeStaleOwed},
	} {
		var f httpapi.Frontier
		if c.f != nil {
			f = c.f
		}
		decision, _ := enforcerWith(t, c.p, c.a, f).Decide(context.Background(), c.class, membership(t), membership(t))
		if decision.Code != c.want {
			t.Errorf("%s: code %q, want %q (reason %q)", c.name, decision.Code, c.want, decision.Reason)
		}
		if !slices.Contains(httpapi.DecisionCodes, decision.Code) {
			t.Errorf("%s: code %q is not in DecisionCodes", c.name, decision.Code)
		}
	}
}
