package httpapi_test

// Tokens here are signed for real and verified by the real verifier, against a key set the
// test publishes. Injecting a Caller and skipping the verifier would leave the only path that
// matters -- the one a request actually takes -- unexercised.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/verify"

	"github.com/anshacerbia2/foundation-reference/internal/httpapi"
)

const (
	testIssuer   = "https://issuer.test"
	testAudience = "foundation-reference"
	testKID      = "test-key"

	// testWorkload is the producer's workload, the one principal_id the intake admits.
	testWorkload = "55555555-5555-4555-8555-55555555550b"
)

// keyBits is foundation-platform's floor rather than a preference: verify discards any RSA
// modulus below 3072 bits while parsing the key set, and every verification then fails as
// "kid unknown and the key set could not be reloaded" -- a message about key distribution
// for a cause that is key size.
const keyBits = 3072

// verify.StaticKeys is the substrate's own KeySource for exactly this case, so there is no
// hand-written stub here to drift from the interface.
func keySet(key *rsa.PrivateKey) verify.StaticKeys {
	return verify.StaticKeys{testKID: &key.PublicKey}
}

func signer(t *testing.T) (*rsa.PrivateKey, *verify.Verifier) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	verifier, err := verify.New(verify.Config{
		Issuer:   testIssuer,
		Audience: testAudience,
		Keys:     keySet(key),
		MaxSkew:  30 * time.Second,
		Requirement: verify.RequirementFunc(func(claims verify.Claims) error {
			if _, ok := claims.String("scope"); !ok {
				return errors.New("the token carries no scope claim")
			}
			return nil
		}),
	})
	if err != nil {
		t.Fatalf("verify.New: %v", err)
	}
	return key, verifier
}

// token mints a PS256 JWT. PS256 is not a choice made here: verify permits exactly one
// algorithm and verifies with rsa.VerifyPSS at PSSSaltLengthEqualsHash, so an RS256 token is
// well formed, correctly claimed, and refused.
func token(t *testing.T, key *rsa.PrivateKey, scope string) string {
	t.Helper()
	return tokenWith(t, key, scope, nil)
}

// tokenWith is token carrying extra claims as well.
func tokenWith(t *testing.T, key *rsa.PrivateKey, scope string, extra map[string]any) string {
	t.Helper()

	now := time.Now().UTC()
	header := map[string]any{"alg": "PS256", "typ": "JWT", "kid": testKID}
	claims := map[string]any{
		"iss":   testIssuer,
		"aud":   []string{testAudience},
		"sub":   "01a05800-0000-7000-8000-000000000001",
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"exp":   now.Add(10 * time.Minute).Unix(),
		"scope": scope,
	}
	for name, value := range extra {
		claims[name] = value
	}

	encode := func(value any) string {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshalling: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(encoded)
	}

	signing := encode(header) + "." + encode(claims)
	digest := sha256sum(signing)
	signature, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// deliveryToken is the producer's workload token: the delivery scope, naming the configured
// workload.
func deliveryToken(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	return tokenWith(t, key, httpapi.DeliveryScope, map[string]any{"principal_id": testWorkload, "subject_type": "workload"})
}

func middleware(t *testing.T, verifier *verify.Verifier, role httpapi.Role) func(http.Handler) http.Handler {
	t.Helper()
	workload := ""
	if role == httpapi.RoleDelivery {
		workload = testWorkload
	}
	built, err := httpapi.Authenticate(verifier, role, workload)
	if err != nil {
		t.Fatalf("Authenticate(%s): %v", role, err)
	}
	return built
}

func served(t *testing.T, chain func(http.Handler) http.Handler, authorization string) *httptest.ResponseRecorder {
	t.Helper()

	reached := false
	handler := chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		caller, ok := httpapi.CallerFrom(r.Context())
		if !ok || caller.Subject == "" {
			t.Error("the handler was reached without a caller in the context")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodPost, "/v1/deliveries", strings.NewReader("{}"))
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code < 300 && !reached {
		t.Error("a successful status was returned without reaching the handler")
	}
	if recorder.Code >= 400 && reached {
		t.Error("the handler ran despite a refusal status")
	}
	return recorder
}

func TestAnAbsentCredentialIsRefused(t *testing.T) {
	_, verifier := signer(t)
	chain := middleware(t, verifier, httpapi.RoleDelivery)

	for _, header := range []string{"", "Basic abc", "Bearer", "Bearer ", "bearer two words"} {
		recorder := served(t, chain, header)
		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("Authorization %q: status %d, want 401", header, recorder.Code)
		}
	}
}

func TestADeliveryTokenIsAcceptedOnTheIntakeRole(t *testing.T) {
	key, verifier := signer(t)
	chain := middleware(t, verifier, httpapi.RoleDelivery)

	recorder := served(t, chain, "Bearer "+deliveryToken(t, key))
	if recorder.Code != http.StatusNoContent {
		t.Errorf("status %d, want 204: %s", recorder.Code, recorder.Body.String())
	}
}

// TestOnlyTheConfiguredWorkloadMayDeliver: the delivery scope is something a realm can grant to
// any client, so the intake admits only the producer's workload principal_id (ADR-GLB-018 §5.4),
// the three conditions identity-control's intake holds Organization Control's token to.
func TestOnlyTheConfiguredWorkloadMayDeliver(t *testing.T) {
	key, verifier := signer(t)
	chain := middleware(t, verifier, httpapi.RoleDelivery)

	for name, extra := range map[string]map[string]any{
		"no principal_id":       {"subject_type": "workload"},
		"another workload":      {"principal_id": "55555555-5555-4555-8555-55555555550c", "subject_type": "workload"},
		"a person":              {"principal_id": testWorkload, "subject_type": "human"},
		"no subject_type":       {"principal_id": testWorkload},
		"a tenant-scoped token": {"principal_id": testWorkload, "subject_type": "workload", "tenant_id": "11111111-1111-4111-8111-11111111111a"},
	} {
		recorder := served(t, chain, "Bearer "+tokenWith(t, key, httpapi.DeliveryScope, extra))
		if recorder.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403: %s", name, recorder.Code, recorder.Body.String())
		}
	}
}

// The delivery role cannot be mounted without the workload it admits, and the caller role admits none.
func TestTheDeliveryRoleNeedsItsWorkload(t *testing.T) {
	_, verifier := signer(t)
	if _, err := httpapi.Authenticate(verifier, httpapi.RoleDelivery, ""); !errors.Is(err, httpapi.ErrNoDeliveringWorkload) {
		t.Errorf("a delivery role with no workload answered %v", err)
	}
	if _, err := httpapi.Authenticate(verifier, httpapi.RoleDelivery, "organization-control"); err == nil {
		t.Error("a delivering workload that is not a principal_id was accepted")
	}
	if _, err := httpapi.Authenticate(verifier, httpapi.RoleCaller, testWorkload); err == nil {
		t.Error("the caller role accepted a delivering workload")
	}
}

// TestACallerTokenCannotDeliver is the separation the two roles exist for. A caller who could
// post to the intake could forge a revocation -- or forge its absence by replaying an older
// version, which the monotonicity guard would faithfully accept as authoritative.
func TestACallerTokenCannotDeliver(t *testing.T) {
	key, verifier := signer(t)
	delivery := middleware(t, verifier, httpapi.RoleDelivery)

	recorder := served(t, delivery, "Bearer "+token(t, key, httpapi.CallerScope))
	if recorder.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403: a caller token was accepted on the intake", recorder.Code)
	}
}

func TestADeliveryTokenCannotInvokeOperations(t *testing.T) {
	key, verifier := signer(t)
	caller := middleware(t, verifier, httpapi.RoleCaller)

	recorder := served(t, caller, "Bearer "+deliveryToken(t, key))
	if recorder.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403: a delivery token was accepted on an operation", recorder.Code)
	}
}

// TestScopeIsMatchedWholeGuardsAgainstSubstringAcceptance is the failure that looks like it
// works: a scope check written as a substring match accepts a token that was never granted
// the scope.
func TestScopeIsMatchedWholeGuardsAgainstSubstringAcceptance(t *testing.T) {
	key, verifier := signer(t)
	chain := middleware(t, verifier, httpapi.RoleDelivery)

	for _, scope := range []string{
		httpapi.DeliveryScope + ".readonly",
		"not-" + httpapi.DeliveryScope,
		"foundation-reference.deliverance",
	} {
		recorder := served(t, chain, "Bearer "+token(t, key, scope))
		if recorder.Code != http.StatusForbidden {
			t.Errorf("scope %q: status %d, want 403", scope, recorder.Code)
		}
	}
}

func TestATokenFromAnotherIssuerIsRefused(t *testing.T) {
	key, _ := signer(t)

	// A verifier for a different issuer, same key material: the signature is valid and the
	// issuer is not, and only the issuer check stands between them.
	other, err := verify.New(verify.Config{
		Issuer:      "https://elsewhere.test",
		Audience:    testAudience,
		Keys:        keySet(key),
		MaxSkew:     30 * time.Second,
		Requirement: verify.RequirementFunc(func(verify.Claims) error { return nil }),
	})
	if err != nil {
		t.Fatalf("verify.New: %v", err)
	}

	recorder := served(t, middleware(t, other, httpapi.RoleDelivery), "Bearer "+deliveryToken(t, key))
	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401 for a token from another issuer", recorder.Code)
	}
}

func TestAnUnknownRoleCannotBeMounted(t *testing.T) {
	_, verifier := signer(t)
	if _, err := httpapi.Authenticate(verifier, httpapi.Role("auditor"), ""); err == nil {
		t.Error("Authenticate accepted a role with no scope mapping")
	}
}

func TestAMissingVerifierIsRefused(t *testing.T) {
	if _, err := httpapi.Authenticate(nil, httpapi.RoleDelivery, testWorkload); err == nil {
		t.Error("Authenticate accepted a nil verifier")
	}
}

// sha256sum keeps the signing helper readable.
func sha256sum(signing string) []byte {
	digest := sha256.Sum256([]byte(signing))
	return digest[:]
}
