package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/id"
)

// Verdict is the authority's answer, and it carries the versions so a caller holding a token
// can tell that the token is stale even though this check just succeeded.
type Verdict struct {
	Granted bool

	MembershipVersion     int64
	TenantSecurityVersion int64
	CheckedAt             time.Time
}

// Authority is what this consumer needs from organization-control for the classes that may not
// read a replica.
//
// Keyed by (Tenant, Principal) rather than by a membership identifier. That is the estate's own
// shape — `POST /v1/context/verify` takes consumer_id, tenant_id, principal_id — and it is the
// right one: validity is a property of a principal in a tenant, and the membership is the
// authority's answer rather than the caller's input.
type Authority interface {
	// Verify answers authoritatively. An error means "unknown", never "not granted".
	Verify(ctx context.Context, tenantID, principalID id.UUID) (Verdict, error)
}

// AuthorityClient calls organization-control's fresh check.
//
// It is the one adapter here that knows the authority's wire shape, so replacing the transport
// touches one file.
type AuthorityClient struct {
	endpoint string
	consumer string
	token    string
	client   *http.Client
}

func NewAuthorityClient(baseURL, consumerID, token string, timeout time.Duration) (*AuthorityClient, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if trimmed == "" {
		return nil, errors.New("httpapi: the authority base URL is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("httpapi: %q is not an absolute URL", baseURL)
	}
	if strings.TrimSpace(consumerID) == "" {
		// The authority meters this call per consumer and refuses an unregistered one, because
		// "a check that could be made anonymously would be a check nobody is accountable for".
		// Refusing here means that arrives as a startup error rather than as a 4xx per request.
		return nil, errors.New("httpapi: a consumer identifier is required; the authority meters the fresh check per consumer")
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("httpapi: a bearer token is required to call the authority")
	}
	if timeout <= 0 {
		return nil, errors.New("httpapi: the authority timeout must be positive")
	}

	return &AuthorityClient{
		endpoint: trimmed + "/v1/context/verify",
		consumer: consumerID,
		token:    token,
		client:   &http.Client{Timeout: timeout},
	}, nil
}

type verifyRequest struct {
	ConsumerID  string  `json:"consumer_id"`
	TenantID    id.UUID `json:"tenant_id"`
	PrincipalID id.UUID `json:"principal_id"`
}

// verifyResponse is the subset of the authority's decision this consumer reads.
//
// Narrow on purpose: the decision also carries membership_id, workspace_id and subject_type on
// a grant, and a consumer that read them would acquire a dependency on fields it does not need
// — and on a refusal those fields are deliberately absent, so code that expected them would
// break on exactly the path that matters.
type verifyResponse struct {
	Granted               bool      `json:"granted"`
	MembershipVersion     int64     `json:"membership_version"`
	TenantSecurityVersion int64     `json:"tenant_security_version"`
	CheckedAt             time.Time `json:"checked_at"`
}

// Verify asks the authority.
//
// A refusal arrives as 200 with granted=false, not as 403. That is the authority's deliberate
// choice and the right one: the caller asked whether a principal holds context, and "no" is a
// complete answer. Reading the status code instead of the body would make a refusal
// indistinguishable from a check that could not be performed — and those two require opposite
// responses here, since one is an answer and the other must fail closed.
func (a *AuthorityClient) Verify(ctx context.Context, tenantID, principalID id.UUID) (Verdict, error) {
	body, err := json.Marshal(verifyRequest{
		ConsumerID:  a.consumer,
		TenantID:    tenantID,
		PrincipalID: principalID,
	})
	if err != nil {
		return Verdict{}, fmt.Errorf("httpapi: encoding the fresh check: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(body))
	if err != nil {
		return Verdict{}, fmt.Errorf("httpapi: building the fresh check: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+a.token)

	response, err := a.client.Do(request)
	if err != nil {
		return Verdict{}, fmt.Errorf("httpapi: reaching the authority: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		// Anything other than 200 is "unknown", including 403. A consumer that treated 403 as
		// "not granted" would report a revoked membership when the truth was that its own
		// credential had been withdrawn — the same refusal for two opposite causes.
		detail, _ := io.ReadAll(io.LimitReader(response.Body, 1<<12))
		return Verdict{}, fmt.Errorf("httpapi: the authority answered %d: %s",
			response.StatusCode, strings.TrimSpace(string(detail)))
	}

	var decoded verifyResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<16)).Decode(&decoded); err != nil {
		return Verdict{}, fmt.Errorf("httpapi: decoding the authority's decision: %w", err)
	}

	return Verdict{
		Granted:               decoded.Granted,
		MembershipVersion:     decoded.MembershipVersion,
		TenantSecurityVersion: decoded.TenantSecurityVersion,
		CheckedAt:             decoded.CheckedAt,
	}, nil
}
