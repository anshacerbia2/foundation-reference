// Package frontier reads the producer's publication frontier and caches it briefly.
//
// It exists because the consumer cannot see gaps in its own applied positions: the outbox takes its
// sequence before the transaction commits, so a number a rolled-back transaction consumed is
// indistinguishable from one still in flight. The producer can tell them apart, because a rolled-back
// row was never in its outbox.
//
// What arrives here is facts and no verdict — highest committed mark, oldest position still owed, how
// old it is. The verdict is the enforcer's, per operation class, because the same lag is acceptable
// for a directory read and unacceptable for a payroll one.
package frontier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Facts is the producer's answer.
type Facts struct {
	HighestCommittedMark  int64
	OldestUnpublishedMark int64
	OldestUnpublishedAge  time.Duration

	// Unpublished is false when the producer owes nothing, in which case the two fields above carry
	// no information. Without it, zero would be ambiguous between "nothing pending" and "pending
	// since the epoch".
	Unpublished bool

	ObservedAt time.Time

	// ReadAt is when this consumer received the answer, which is not when the producer observed it.
	// A cached answer ages from here, and the two instants differ by the round trip.
	ReadAt time.Time
}

// Age is how stale this answer itself is.
func (f Facts) Age(now time.Time) time.Duration {
	if f.ReadAt.IsZero() {
		return 0
	}
	return now.Sub(f.ReadAt)
}

type response struct {
	HighestCommittedMark        int64   `json:"highest_committed_mark"`
	OldestUnpublishedMark       int64   `json:"oldest_unpublished_mark"`
	OldestUnpublishedAgeSeconds float64 `json:"oldest_unpublished_age_seconds"`
	Unpublished                 bool    `json:"unpublished"`
	ObservedAt                  string  `json:"observed_at"`
}

// Client reads the frontier, caching it for a short interval.
//
// Cached because an enforcement check happens per request and this is a network call. The interval is
// bounded by the strictest budget that consults it, so caching can only ever make an answer look
// older than it is — never fresher. Rounding the other way would let a cache hide exactly the lag it
// exists to report.
type Client struct {
	endpoint string
	token    string
	client   *http.Client
	ttl      time.Duration
	now      func() time.Time

	mu     sync.Mutex
	cached Facts
	valid  bool
}

func NewClient(baseURL, token string, timeout, ttl time.Duration) (*Client, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if trimmed == "" {
		return nil, errors.New("frontier: the authority base URL is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("frontier: %q is not an absolute URL", baseURL)
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("frontier: a bearer token is required")
	}
	if timeout <= 0 || ttl <= 0 {
		return nil, errors.New("frontier: the timeout and the cache interval must be positive")
	}

	return &Client{
		endpoint: trimmed + "/v1/projections/frontier",
		token:    token,
		client:   &http.Client{Timeout: timeout},
		ttl:      ttl,
		now:      time.Now,
	}, nil
}

// Frontier returns the producer's facts, from cache when the cached answer is younger than the
// interval.
//
// An error is returned rather than a stale cached answer when the read fails. The caller must not be
// able to mistake "the producer could not be reached" for "the producer owes nothing" — the first is
// unknown and the second is a fact, and only one of them permits serving from a replica.
func (c *Client) Frontier(ctx context.Context) (Facts, error) {
	now := c.now().UTC()

	c.mu.Lock()
	if c.valid && now.Sub(c.cached.ReadAt) < c.ttl {
		cached := c.cached
		c.mu.Unlock()
		return cached, nil
	}
	c.mu.Unlock()

	facts, err := c.read(ctx, now)
	if err != nil {
		return Facts{}, err
	}

	c.mu.Lock()
	c.cached, c.valid = facts, true
	c.mu.Unlock()

	return facts, nil
}

func (c *Client) read(ctx context.Context, now time.Time) (Facts, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return Facts{}, fmt.Errorf("frontier: building the request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+c.token)

	httpResponse, err := c.client.Do(request)
	if err != nil {
		return Facts{}, fmt.Errorf("frontier: reaching the authority: %w", err)
	}
	defer func() { _ = httpResponse.Body.Close() }()

	if httpResponse.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(httpResponse.Body, 1<<12))
		return Facts{}, fmt.Errorf("frontier: the authority answered %d: %s",
			httpResponse.StatusCode, strings.TrimSpace(string(detail)))
	}

	var decoded response
	if err := json.NewDecoder(io.LimitReader(httpResponse.Body, 1<<16)).Decode(&decoded); err != nil {
		return Facts{}, fmt.Errorf("frontier: decoding the answer: %w", err)
	}

	observed, err := time.Parse(time.RFC3339Nano, decoded.ObservedAt)
	if err != nil {
		// Refused rather than defaulted to now(). An answer whose instant cannot be read cannot be
		// aged, and treating it as current is the one interpretation that is never safe.
		return Facts{}, fmt.Errorf("frontier: observed_at is not a timestamp: %w", err)
	}

	return Facts{
		HighestCommittedMark:  decoded.HighestCommittedMark,
		OldestUnpublishedMark: decoded.OldestUnpublishedMark,
		OldestUnpublishedAge:  time.Duration(decoded.OldestUnpublishedAgeSeconds * float64(time.Second)),
		Unpublished:           decoded.Unpublished,
		ObservedAt:            observed.UTC(),
		ReadAt:                now,
	}, nil
}
