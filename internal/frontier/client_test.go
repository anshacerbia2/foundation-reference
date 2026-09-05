package frontier

// The frontier client's decoding, which is where two silent-permissiveness traps live.
//
// Both are the same shape: a field the producer did not send, decoded into a zero value that happens
// to mean "everything is fine". An unparseable instant becoming now(), and an absent dead-letter debt
// becoming no debt. Neither is a hypothetical -- a producer one deployment behind sends exactly this.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func client(t *testing.T, body string, status int) *Client {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Errorf("the request carried Authorization %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	built, err := NewClient(server.URL, "token", 5*time.Second, time.Second)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return built
}

const completeAnswer = `{
  "highest_committed_mark": 120,
  "oldest_unpublished_mark": 90,
  "oldest_unpublished_age_seconds": 12.5,
  "unpublished": true,
  "security_dead_lettered": 2,
  "oldest_security_dead_letter_age_seconds": 180,
  "security_debt": true,
  "observed_at": "2026-09-05T04:05:06.789Z"
}`

func TestTheClientReadsEveryFact(t *testing.T) {
	facts, err := client(t, completeAnswer, http.StatusOK).Frontier(context.Background())
	if err != nil {
		t.Fatalf("Frontier: %v", err)
	}

	switch {
	case facts.HighestCommittedMark != 120:
		t.Errorf("highest committed mark = %d", facts.HighestCommittedMark)
	case facts.OldestUnpublishedAge != 12500*time.Millisecond:
		t.Errorf("oldest unpublished age = %s", facts.OldestUnpublishedAge)
	case !facts.Unpublished:
		t.Error("the owed pool was decoded as empty")
	case facts.SecurityDeadLettered != 2:
		t.Errorf("dead-lettered count = %d", facts.SecurityDeadLettered)
	case facts.OldestSecurityDeadLetterAge != 3*time.Minute:
		t.Errorf("oldest debt age = %s", facts.OldestSecurityDeadLetterAge)
	case !facts.SecurityDebt:
		t.Error("the debt flag was decoded as false while the answer set it")
	case facts.ReadAt.IsZero():
		t.Error("ReadAt is unset, so a cached answer could not be aged")
	}
}

// TestAnAnswerWithoutTheDebtFieldIsRefused is the compatibility decision, stated as a test.
//
// A producer that predates the debt contract sends every other field and omits this one. Decoded to
// false, its answer reads "nothing owed, nothing abandoned" -- the most reassuring answer the frontier
// can give, from a producer that cannot actually tell. That is worse than an error, because it is
// indistinguishable from the healthy case and it appears the moment the two sides are deployed out of
// step rather than at the moment someone changes the code.
func TestAnAnswerWithoutTheDebtFieldIsRefused(t *testing.T) {
	legacy := `{
      "highest_committed_mark": 120,
      "oldest_unpublished_mark": 0,
      "oldest_unpublished_age_seconds": 0,
      "unpublished": false,
      "observed_at": "2026-09-05T04:05:06.789Z"
    }`

	facts, err := client(t, legacy, http.StatusOK).Frontier(context.Background())
	if err == nil {
		t.Fatalf("an answer with no debt field was accepted as %+v", facts)
	}
	if !strings.Contains(err.Error(), "security_dead_lettered") {
		t.Errorf("the error does not name the missing contract: %v", err)
	}
}

// A false debt flag is a fact and must be accepted. Refusing it too would leave the producer no way
// to report health, and a contract with no healthy answer is a contract nobody deploys.
func TestAnExplicitlyEmptyDebtIsAccepted(t *testing.T) {
	healthy := `{
      "highest_committed_mark": 120,
      "unpublished": false,
      "security_dead_lettered": 0,
      "oldest_security_dead_letter_age_seconds": 0,
      "security_debt": false,
      "observed_at": "2026-09-05T04:05:06.789Z"
    }`

	facts, err := client(t, healthy, http.StatusOK).Frontier(context.Background())
	if err != nil {
		t.Fatalf("Frontier: %v", err)
	}
	if facts.SecurityDebt || facts.Unpublished {
		t.Errorf("a healthy answer decoded as %+v", facts)
	}
}

// TestAFailedReadIsNotServedFromCache keeps "the producer could not be reached" apart from "the
// producer owes nothing". Only the second permits serving from a replica, and a cache that answered
// the first with the second would hide exactly the outage it was asked about.
func TestAFailedReadIsNotServedFromCache(t *testing.T) {
	var answer = completeAnswer
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if answer == "" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(answer))
	}))
	t.Cleanup(server.Close)

	// A one-nanosecond cache interval, so the second call cannot be a cache hit for timing reasons
	// and the assertion is about the failure path rather than about the clock.
	built, err := NewClient(server.URL, "token", 5*time.Second, time.Nanosecond)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := built.Frontier(context.Background()); err != nil {
		t.Fatalf("the first read failed: %v", err)
	}

	answer = ""
	if facts, err := built.Frontier(context.Background()); err == nil {
		t.Errorf("a failed read was answered from cache as %+v", facts)
	}
}
