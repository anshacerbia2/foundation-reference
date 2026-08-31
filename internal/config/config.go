// Package config reads the environment once, at startup, and refuses to start on a value
// that would only fail later.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	Deployable = "foundation-reference"

	// System is the SAD this deployable belongs to. It exists to prove one property of
	// SAD-004: that an authority change in organization-control becomes enforcement in
	// another process, with a delay that can be measured.
	System = "SAD-004"
)

type Config struct {
	DatabaseURL   string
	ListenAddress string

	// ConsumerName is the logical consumer identity written to platform.processed_event.
	// It must be stable across restarts and across replicas: inbox.Guard deduplicates per
	// (event_id, consumer), so a name derived from a hostname would let a second replica
	// apply an effect a first replica already applied.
	ConsumerName string

	// MaxProjectionAge bounds fail-open. A LOW_RISK operation is allowed while the
	// projection is younger than this; past it the operation is refused rather than served
	// from state old enough to have missed a revocation.
	//
	// There is no safe default for "unbounded", which is why this has a value rather than
	// being optional: an unbounded fail-open is a revocation that silently never applies.
	MaxProjectionAge time.Duration

	// AuthorityBaseURL is organization-control. PRIVILEGED and IRREVERSIBLE operations ask
	// it directly instead of reading the projection, because an operation that cannot be
	// undone must not be authorised by a replica that is allowed to lag.
	AuthorityBaseURL string

	AuthorityTimeout time.Duration

	// Token verification. Required rather than optional: this deployable writes a projection
	// that decides whether other people's operations proceed, and a build that can start
	// without a verifier is a build that can be deployed with authentication switched off.
	TokenIssuer   string
	TokenAudience string
	JWKSURL       string
	TokenMaxSkew  time.Duration

	HTTPReadTimeout    time.Duration
	HTTPWriteTimeout   time.Duration
	HTTPRequestTimeout time.Duration
	HTTPShutdownGrace  time.Duration
	HTTPMaxInFlight    int64

	LogLevel string
}

func Load() (Config, error) {
	var cfg Config
	var problems []error

	cfg.DatabaseURL = strings.TrimSpace(os.Getenv("REFERENCE_DATABASE_URL"))
	if cfg.DatabaseURL == "" {
		problems = append(problems, errors.New("REFERENCE_DATABASE_URL is required"))
	}

	cfg.ConsumerName = stringOr("REFERENCE_CONSUMER_NAME", Deployable)
	cfg.ListenAddress = stringOr("REFERENCE_LISTEN_ADDRESS", "127.0.0.1:8096")
	cfg.AuthorityBaseURL = strings.TrimSpace(os.Getenv("REFERENCE_AUTHORITY_BASE_URL"))
	cfg.LogLevel = stringOr("LOG_LEVEL", "info")

	cfg.TokenIssuer = strings.TrimSpace(os.Getenv("REFERENCE_TOKEN_ISSUER"))
	if cfg.TokenIssuer == "" {
		problems = append(problems, errors.New("REFERENCE_TOKEN_ISSUER is required"))
	}
	cfg.TokenAudience = stringOr("REFERENCE_TOKEN_AUDIENCE", Deployable)
	cfg.JWKSURL = strings.TrimSpace(os.Getenv("REFERENCE_JWKS_URL"))
	if cfg.JWKSURL == "" {
		problems = append(problems, errors.New("REFERENCE_JWKS_URL is required"))
	}

	// The ceiling is the substrate's, not a preference: STD-IAM-002 §3.5 caps it at 60s, and
	// verify refuses a larger value. Stated here so a misconfiguration is a startup error
	// rather than a construction failure further down.
	cfg.TokenMaxSkew = durationOr("REFERENCE_TOKEN_MAX_SKEW", 30*time.Second, &problems)
	if cfg.TokenMaxSkew > 60*time.Second {
		problems = append(problems, fmt.Errorf(
			"REFERENCE_TOKEN_MAX_SKEW is %s; STD-IAM-002 §3.5 caps clock skew at 60s", cfg.TokenMaxSkew))
	}

	cfg.MaxProjectionAge = durationOr("REFERENCE_MAX_PROJECTION_AGE", 60*time.Second, &problems)
	cfg.AuthorityTimeout = durationOr("REFERENCE_AUTHORITY_TIMEOUT", 2*time.Second, &problems)

	cfg.HTTPReadTimeout = durationOr("HTTP_READ_TIMEOUT", 10*time.Second, &problems)
	cfg.HTTPWriteTimeout = durationOr("HTTP_WRITE_TIMEOUT", 30*time.Second, &problems)
	cfg.HTTPRequestTimeout = durationOr("HTTP_REQUEST_TIMEOUT", 5*time.Second, &problems)
	cfg.HTTPShutdownGrace = durationOr("HTTP_SHUTDOWN_GRACE", 20*time.Second, &problems)
	cfg.HTTPMaxInFlight = int64(intOr("HTTP_MAX_IN_FLIGHT", 256, &problems))

	// A fail-open window wider than the request timeout is not a window: every request
	// would be served from a projection nobody re-checked within the life of the request.
	if cfg.MaxProjectionAge <= 0 {
		problems = append(problems, errors.New("REFERENCE_MAX_PROJECTION_AGE must be positive: an unbounded fail-open is a revocation that never applies"))
	}

	if len(problems) > 0 {
		return Config{}, errors.Join(problems...)
	}
	return cfg, nil
}

func stringOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func durationOr(key string, fallback time.Duration, problems *[]error) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		*problems = append(*problems, fmt.Errorf("%s is not a duration: %q", key, raw))
		return fallback
	}
	return value
}

func intOr(key string, fallback int, problems *[]error) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	var value int
	if _, err := fmt.Sscanf(raw, "%d", &value); err != nil {
		*problems = append(*problems, fmt.Errorf("%s is not an integer: %q", key, raw))
		return fallback
	}
	return value
}
