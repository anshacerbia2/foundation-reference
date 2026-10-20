package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-reference/internal/projection"
)

func seconds(n int64) *int64 { return &n }

// A run is due when none is recorded, when a restore asked for one, or when it would otherwise fall
// due before the next check; and not before.
func TestDue(t *testing.T) {
	requested := time.Now()
	for name, c := range map[string]struct {
		registration Registration
		want         bool
	}{
		"never reconciled":         {Registration{IntervalSeconds: 900}, true},
		"requested by a restore":   {Registration{IntervalSeconds: 900, AgeSeconds: seconds(5), RequestedAt: &requested}, true},
		"well inside the interval": {Registration{IntervalSeconds: 900, AgeSeconds: seconds(100)}, false},
		"one check before due":     {Registration{IntervalSeconds: 900, AgeSeconds: seconds(840)}, true},
		"just short of that":       {Registration{IntervalSeconds: 900, AgeSeconds: seconds(839)}, false},
		"past the interval":        {Registration{IntervalSeconds: 900, AgeSeconds: seconds(5000)}, true},
		"no interval declared":     {Registration{AgeSeconds: seconds(5000)}, false},
	} {
		if got, reason := Due(c.registration, time.Minute); got != c.want {
			t.Errorf("%s: due = %v (%q), want %v", name, got, reason, c.want)
		}
	}
}

type producerStub struct {
	mu           sync.Mutex
	registration Registration
	err          error
	reports      []projection.Report
}

func (p *producerStub) Registration(context.Context) (Registration, error) {
	return p.registration, p.err
}

func (p *producerStub) Reconcile(_ context.Context, report projection.Report) (Result, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reports = append(p.reports, report)
	return Result{Mark: report.Mark, Findings: []Finding{{Classification: "extra"}}}, nil
}

type reporterStub struct {
	report projection.Report
	err    error
	calls  int
}

func (r *reporterStub) Report(context.Context) (projection.Report, error) {
	r.calls++
	return r.report, r.err
}

// A check that is not due reads nothing of the projection and sends nothing; a due one sends the report.
func TestTickSendsTheReportOnlyWhenDue(t *testing.T) {
	report := projection.Report{ConsumerID: "foundation-reference", Mark: 7,
		Rows: []projection.ReportedRow{{MembershipID: "m", MembershipVersion: 2}}}

	quiet := &producerStub{registration: Registration{IntervalSeconds: 900, AgeSeconds: seconds(10)}}
	reporter := &reporterStub{report: report}
	outcome, err := (&Scheduler{Reporter: reporter, Producer: quiet, Check: time.Minute}).Tick(context.Background())
	if err != nil || outcome.Ran || reporter.calls != 0 || len(quiet.reports) != 0 {
		t.Fatalf("a check inside the interval ran: outcome %+v, error %v, reports %d", outcome, err, len(quiet.reports))
	}

	due := &producerStub{registration: Registration{IntervalSeconds: 900}}
	outcome, err = (&Scheduler{Reporter: reporter, Producer: due, Check: time.Minute}).Tick(context.Background())
	if err != nil || !outcome.Ran || outcome.Rows != 1 || outcome.Result.Extra() != 1 {
		t.Fatalf("a due check: outcome %+v, error %v", outcome, err)
	}
	if len(due.reports) != 1 || due.reports[0].Mark != 7 {
		t.Errorf("the producer received %+v, want the report at mark 7", due.reports)
	}
}

// A consumer that has not bootstrapped sends nothing: there is no copy to compare yet.
func TestTickSendsNothingBeforeTheBootstrap(t *testing.T) {
	due := &producerStub{registration: Registration{IntervalSeconds: 900}}
	reporter := &reporterStub{err: projection.ErrNotBootstrapped}
	_, err := (&Scheduler{Reporter: reporter, Producer: due, Check: time.Minute}).Tick(context.Background())
	if !errors.Is(err, projection.ErrNotBootstrapped) || len(due.reports) != 0 {
		t.Errorf("Tick returned %v and sent %d report(s), want ErrNotBootstrapped and none", err, len(due.reports))
	}
}

// Run checks at once, without waiting a check interval.
func TestRunChecksAtOnce(t *testing.T) {
	due := &producerStub{registration: Registration{IntervalSeconds: 900}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		(&Scheduler{Reporter: &reporterStub{report: projection.Report{Mark: 1}}, Producer: due, Check: time.Hour,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Run(ctx)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		due.mu.Lock()
		n := len(due.reports)
		due.mu.Unlock()
		if n == 1 {
			cancel()
			<-done
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	t.Fatal("Run did not reconcile at once")
}

// The client reads the consumer's own registration and posts the report in the reconcile route's shape,
// as the consumer, with no administrative reason: the route admits a consumer for itself.
func TestTheClientSpeaksTheProducersContract(t *testing.T) {
	var posted map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer consumer-token" {
			t.Errorf("%s %s carried %q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		if r.Header.Get("X-Administrative-Reason") != "" {
			t.Errorf("%s %s carried an administrative reason", r.Method, r.URL.Path)
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projections/consumers/foundation-reference":
			_, _ = io.WriteString(w, `{"consumer_id":"foundation-reference","reconciliation_interval_seconds":900,
				"reconciliation_age_seconds":12,"reconciliation_requested_at":null}`)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/projections/reconcile":
			if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
				t.Errorf("decoding the report: %v", err)
			}
			_, _ = io.WriteString(w, `{"consumer_id":"foundation-reference","mark":7,"run_at":"2026-10-20T10:00:00Z",
				"findings":[{"classification":"missing","membership_id":"m"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "consumer-token", "foundation-reference", time.Second)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	registration, err := client.Registration(context.Background())
	if err != nil || registration.IntervalSeconds != 900 || registration.AgeSeconds == nil ||
		*registration.AgeSeconds != 12 || registration.RequestedAt != nil {
		t.Fatalf("Registration: %+v, %v", registration, err)
	}
	result, err := client.Reconcile(context.Background(), projection.Report{ConsumerID: "foundation-reference",
		Mark: 7, Rows: []projection.ReportedRow{}})
	if err != nil || result.Mark != 7 || len(result.Findings) != 1 {
		t.Fatalf("Reconcile: %+v, %v", result, err)
	}
	rows, isArray := posted["rows"].([]any)
	if posted["consumer_id"] != "foundation-reference" || posted["mark"] != float64(7) || !isArray || len(rows) != 0 {
		t.Errorf("posted %v, want consumer_id, mark and an empty rows array", posted)
	}
}

// A 403 is ErrRefused and a 404 is ErrNotRegistered, so the schedule can tell them from a fault.
func TestTheClientNamesARefusal(t *testing.T) {
	for status, want := range map[int]error{
		http.StatusForbidden: ErrRefused, http.StatusUnauthorized: ErrRefused, http.StatusNotFound: ErrNotRegistered,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
		client, _ := NewClient(server.URL, "t", "foundation-reference", time.Second)
		if _, err := client.Reconcile(context.Background(), projection.Report{}); !errors.Is(err, want) {
			t.Errorf("%d: %v, want %v", status, err, want)
		}
		server.Close()
	}
}
