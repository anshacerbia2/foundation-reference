package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-reference/internal/httpapi"
)

// STD-IAM-002 §3.5 step 8: a token issued for a Tenant acts in that Tenant alone. One selecting
// another Tenant than the path names, or carrying a tenant_id that is no identifier, is refused
// before the decision is consulted; one selecting the path's Tenant, or none, reaches the decision,
// which reads the projection.
func TestATokenActsOnlyInTheTenantItWasIssuedFor(t *testing.T) {
	key, verifier := signer(t)
	surface, err := httpapi.Routes(httpapi.Config{
		Projector: stubDeliveries{},
		Enforcer:  enforcer(t, stubProjection{age: time.Second}, nil),
		Delivery:  passthrough,
		Caller:    middleware(t, verifier, httpapi.RoleCaller),
	})
	if err != nil {
		t.Fatalf("Routes: %v", err)
	}
	path := "01a05800-0000-7000-8000-0000000000aa"
	for name, c := range map[string]struct {
		extra   map[string]any
		decided bool
	}{
		"no tenant_id":           {nil, true},
		"the path's Tenant":      {map[string]any{"tenant_id": path}, true},
		"another Tenant":         {map[string]any{"tenant_id": "01a05800-0000-7000-8000-0000000000bb"}, false},
		"a tenant_id not a UUID": {map[string]any{"tenant_id": "acme"}, false},
		"an empty tenant_id":     {map[string]any{"tenant_id": ""}, false},
	} {
		request := httptest.NewRequest(http.MethodGet, "/v1/directory/"+path, nil)
		request.Header.Set("Authorization", "Bearer "+tokenWith(t, key, httpapi.CallerScope, c.extra))
		recorder := httptest.NewRecorder()
		surface.API.ServeHTTP(recorder, request)

		var body map[string]any
		_ = json.Unmarshal(recorder.Body.Bytes(), &body)
		_, decided := body["allowed"]
		if decided != c.decided {
			t.Errorf("%s: answered %d %v; decided=%t, want %t", name, recorder.Code, body, decided, c.decided)
		}
		if !c.decided && recorder.Code != http.StatusForbidden {
			t.Errorf("%s: answered %d, want 403", name, recorder.Code)
		}
	}
}
