package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/anshacerbia2/foundation-platform/verify"
)

// Two distinct authorities reach this service, and conflating them would be the defect worth
// avoiding rather than the code worth saving.
//
// A delivery is a workload writing to this consumer's projection: it may apply events and
// nothing else. A caller of an operation is a principal asking whether it may act: it may
// read the enforcement answer and may not write the projection. One role that admits both
// would let anyone who can call an operation forge a revocation — or, worse, forge its
// absence by replaying an older version.
type Role string

const (
	// RoleDelivery may post to the intake. Nothing else.
	RoleDelivery Role = "delivery"

	// RoleCaller may invoke the protected operations. It cannot write the projection.
	RoleCaller Role = "caller"
)

const (
	// DeliveryScope is the claim value a delivery token must carry. It is checked as an
	// exact string rather than as a prefix: "reference-consumer.deliver.readonly" must not
	// satisfy a rule written for "reference-consumer.deliver".
	DeliveryScope = "reference-consumer.deliver"

	// CallerScope is what an operation caller must carry.
	CallerScope = "reference-consumer.operate"

	// scopeClaim is the claim the estate puts scopes in. It is configuration in a real
	// deployment because it is a property of the realm; here it is fixed because this
	// deployable exists to prove one property and a second knob would not help.
	scopeClaim = "scope"
)

var (
	ErrNoVerifier    = errors.New("httpapi: a verifier is required")
	ErrNoCredential  = errors.New("httpapi: a bearer token is required")
	ErrWrongRole     = errors.New("httpapi: the token does not carry this role")
	ErrNotAuthorised = errors.New("httpapi: the token is authentic and carries no applicable scope")
)

type callerKey struct{}

// Caller is what an authenticated request carries forward.
type Caller struct {
	Subject string
	Role    Role
}

// CallerFrom returns the authenticated caller. The second result is false on an
// unauthenticated request, and every handler that needs a caller must check it rather than
// treating the zero value as anonymous-but-allowed.
func CallerFrom(ctx context.Context) (Caller, bool) {
	caller, ok := ctx.Value(callerKey{}).(Caller)
	return caller, ok
}

// Authenticate builds middleware for one role.
//
// It is per-role rather than one middleware plus a check inside each handler, because a
// handler that forgets the check is indistinguishable from one that does not need it. Here
// the role is chosen where the route is mounted, beside the security class, so both
// properties of a route are stated in the same place.
func Authenticate(verifier *verify.Verifier, role Role) (func(http.Handler) http.Handler, error) {
	if verifier == nil {
		return nil, ErrNoVerifier
	}

	var required string
	switch role {
	case RoleDelivery:
		required = DeliveryScope
	case RoleCaller:
		required = CallerScope
	default:
		return nil, fmt.Errorf("httpapi: unknown role %q", role)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := bearer(r)
			if err != nil {
				// 401: we do not know who this is.
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
				return
			}

			claims, err := verifier.Verify(token)
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "the token was not accepted",
				})
				return
			}

			if !hasScope(claims, required) {
				// 403, not 401, and the difference is the point: the token is authentic, so
				// "we do not know who you are" would be false. Its claims confer no scope
				// for this role.
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error": fmt.Sprintf("this route requires the %q scope", required),
				})
				return
			}

			ctx := context.WithValue(r.Context(), callerKey{}, Caller{Subject: claims.Subject, Role: role})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}, nil
}

func bearer(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", ErrNoCredential
	}
	// The scheme is compared case-insensitively per RFC 7235, and the remainder is not
	// trimmed of internal whitespace: a token with a space in it is not a token.
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "bearer") {
		return "", ErrNoCredential
	}
	token = strings.TrimSpace(token)
	if token == "" || strings.ContainsAny(token, " \t") {
		return "", ErrNoCredential
	}
	return token, nil
}

// hasScope reads the space-delimited scope claim, comparing whole entries.
//
// A substring match would accept "reference-consumer.deliver" inside
// "not-reference-consumer.deliverance", which is the classic way a scope check passes for a
// token that was never granted the scope.
func hasScope(claims verify.Claims, required string) bool {
	raw, ok := claims.String(scopeClaim)
	if !ok {
		return false
	}
	for _, granted := range strings.Fields(raw) {
		if granted == required {
			return true
		}
	}
	return false
}
