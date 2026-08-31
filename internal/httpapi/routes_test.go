package httpapi_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/event"

	"github.com/anshacerbia2/foundation-reference/internal/httpapi"
	"github.com/anshacerbia2/foundation-reference/internal/projection"
)

type stubDeliveries struct{}

func (stubDeliveries) Apply(context.Context, event.Envelope) (projection.Outcome, error) {
	return projection.Outcome{Applied: true}, nil
}

func (stubDeliveries) Age(context.Context) (time.Duration, error) { return time.Second, nil }

func passthrough(next http.Handler) http.Handler { return next }

// TestRoutesRefuseToMountWithoutAuthentication covers the one configuration mistake that
// produces no symptom at all: everything works, and nothing is authenticated.
//
// A nil middleware defaulted to a pass-through would leave the intake open, and an open intake
// is a projection anyone can write — including with a forged older version, which the
// monotonicity guard would then accept as authoritative and refuse to correct.
func TestRoutesRefuseToMountWithoutAuthentication(t *testing.T) {
	base := httpapi.Config{
		Projector: stubDeliveries{},
		Enforcer:  enforcer(t, stubProjection{age: time.Second}, nil),
	}

	missingDelivery := base
	missingDelivery.Caller = passthrough
	if _, err := httpapi.Routes(missingDelivery); err == nil {
		t.Error("Routes mounted with no delivery authentication")
	} else if !strings.Contains(err.Error(), "delivery authentication") {
		t.Errorf("error was %q, which does not name delivery authentication", err)
	}

	missingCaller := base
	missingCaller.Delivery = passthrough
	if _, err := httpapi.Routes(missingCaller); err == nil {
		t.Error("Routes mounted with no caller authentication")
	} else if !strings.Contains(err.Error(), "caller authentication") {
		t.Errorf("error was %q, which does not name caller authentication", err)
	}
}

// TestRoutesMountWithBothMiddlewares is the positive control. Without it the test above would
// still pass if Routes always failed, which would prove nothing about the reason.
func TestRoutesMountWithBothMiddlewares(t *testing.T) {
	surface, err := httpapi.Routes(httpapi.Config{
		Projector: stubDeliveries{},
		Enforcer:  enforcer(t, stubProjection{age: time.Second}, nil),
		Delivery:  passthrough,
		Caller:    passthrough,
	})
	if err != nil {
		t.Fatalf("Routes: %v", err)
	}
	if surface.Probes == nil || surface.API == nil {
		t.Error("Routes returned a surface with a nil mux")
	}
}
