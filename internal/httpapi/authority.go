package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/id"
)

// AuthorityClient asks organization-control directly, for the classes that must not read a
// replica.
//
// It is the one adapter in this repository that knows the authority's URL shape. Everything
// else depends on the Authority interface declared beside its caller, so replacing this with
// a different transport touches one file.
type AuthorityClient struct {
	base   string
	client *http.Client
}

func NewAuthorityClient(baseURL string, timeout time.Duration) (*AuthorityClient, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if trimmed == "" {
		return nil, errors.New("httpapi: the authority base URL is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("httpapi: %q is not an absolute URL", baseURL)
	}
	if timeout <= 0 {
		return nil, errors.New("httpapi: the authority timeout must be positive")
	}
	return &AuthorityClient{base: trimmed, client: &http.Client{Timeout: timeout}}, nil
}

// MembershipValid returns an error rather than false when the answer is unknown.
//
// The distinction carries the safety property: a transport failure that returned false
// would read as "the authority says no", and the caller would refuse for the wrong reason —
// which is survivable — while a transport failure that returned true would admit a revoked
// caller, which is not. Only the caller decides what an unknown answer means, and for these
// classes it decides to refuse.
func (a *AuthorityClient) MembershipValid(ctx context.Context, membershipID id.UUID) (bool, error) {
	endpoint := fmt.Sprintf("%s/v1/memberships/%s/validity", a.base, membershipID)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, fmt.Errorf("httpapi: building the authority request: %w", err)
	}
	request.Header.Set("Accept", "application/json")

	response, err := a.client.Do(request)
	if err != nil {
		return false, fmt.Errorf("httpapi: reaching the authority: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	switch response.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusForbidden, http.StatusNotFound, http.StatusGone:
		// A definite negative from the authority. Distinct from a transport failure, and
		// the only case where false is the truth rather than an assumption.
		return false, nil
	default:
		return false, fmt.Errorf("httpapi: the authority answered %d", response.StatusCode)
	}
}
