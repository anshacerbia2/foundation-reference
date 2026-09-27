package telemetry

import (
	"context"
	"errors"
	"os"
	"regexp"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/anshacerbia2/foundation-reference/internal/httpapi"
)

type fixedAge struct {
	age time.Duration
	err error
}

func (f fixedAge) Age(context.Context) (time.Duration, error) { return f.age, f.err }

func collect(t *testing.T, a ager, record func(*Metrics)) metricdata.ResourceMetrics {
	t.Helper()
	manual := sdkmetric.NewManualReader()
	m, err := New(sdkmetric.NewMeterProvider(sdkmetric.WithReader(manual)), a, time.Minute,
		"foundation-reference", "SAD-004")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	record(m)
	var rm metricdata.ResourceMetrics
	if err := manual.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rm
}

func find(rm metricdata.ResourceMetrics, name string) (metricdata.Aggregation, bool) {
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name == name {
				return m.Data, true
			}
		}
	}
	return nil, false
}

// A refusal is counted under its class and its code, with the identity every series carries.
func TestDecisionsAndDeliveriesAreCountedWithTheirLabels(t *testing.T) {
	rm := collect(t, fixedAge{age: 5 * time.Second}, func(m *Metrics) {
		m.Decision(context.Background(), httpapi.LowRisk, httpapi.Decision{Allow: false, Code: httpapi.CodeStaleSecurityDebt})
		m.Decision(context.Background(), httpapi.LowRisk, httpapi.Decision{Allow: false, Code: httpapi.CodeStaleSecurityDebt})
		m.Delivery(context.Background(), httpapi.DeliveryRefused)
	})

	data, ok := find(rm, Decisions.Name)
	if !ok {
		t.Fatal("no decision counter was exported")
	}
	sum := data.(metricdata.Sum[int64])
	if len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 2 {
		t.Fatalf("decision points = %+v, want one series counting 2", sum.DataPoints)
	}
	for key, want := range map[string]string{
		"class": "LOW_RISK", "allowed": "false", "code": httpapi.CodeStaleSecurityDebt,
		"deployable": "foundation-reference", "system": "SAD-004",
	} {
		if v, ok := sum.DataPoints[0].Attributes.Value(attribute.Key(key)); !ok || v.AsString() != want {
			t.Errorf("decision attribute %s = %v, want %q", key, v.AsString(), want)
		}
	}

	data, ok = find(rm, Deliveries.Name)
	if !ok {
		t.Fatal("no delivery counter was exported")
	}
	if v, _ := data.(metricdata.Sum[int64]).DataPoints[0].Attributes.Value("outcome"); v.AsString() != httpapi.DeliveryRefused {
		t.Errorf("delivery outcome = %q, want refused", v.AsString())
	}

	data, ok = find(rm, ProjectionAge.Name)
	if !ok || data.(metricdata.Gauge[float64]).DataPoints[0].Value != 5 {
		t.Errorf("projection age = %+v, want 5s", data)
	}
	data, ok = find(rm, MaxAge.Name)
	if !ok || data.(metricdata.Gauge[float64]).DataPoints[0].Value != 60 {
		t.Errorf("max age = %+v, want 60s", data)
	}
}

// A projection with no age observes none: a zero would read as perfectly fresh.
func TestAColdProjectionObservesNoAge(t *testing.T) {
	rm := collect(t, fixedAge{err: errors.New("not bootstrapped")}, func(*Metrics) {})
	if data, ok := find(rm, ProjectionAge.Name); ok && len(data.(metricdata.Gauge[float64]).DataPoints) > 0 {
		t.Errorf("a cold projection reported an age: %+v", data)
	}
	if _, ok := find(rm, MaxAge.Name); !ok {
		t.Error("the budget was not exported, so the absent-telemetry alert would fire for a cold consumer")
	}
}

var ruleSeries = regexp.MustCompile(`\breference_[a-z_]+\b`)

// Every series a rule reads must be one this package exports, and every code a rule selects must
// be one the enforcer can produce.
func TestTheRulesReadOnlyWhatIsExported(t *testing.T) {
	rules, err := os.ReadFile("../../deploy/alerts/foundation-reference.rules.yml")
	if err != nil {
		t.Fatalf("reading the rules: %v", err)
	}
	exported := map[string]bool{}
	for _, i := range Instruments {
		exported[i.PrometheusName()] = true
	}
	names := ruleSeries.FindAllString(string(rules), -1)
	if len(names) == 0 {
		t.Fatal("found no series in the rules; the pattern no longer matches them")
	}
	for _, name := range names {
		if !exported[name] {
			t.Errorf("the rules read %s, which no instrument exports", name)
		}
	}

	known := map[string]bool{}
	for _, code := range httpapi.DecisionCodes {
		known[code] = true
	}
	for _, match := range regexp.MustCompile(`code="([a-z_]+)"`).FindAllStringSubmatch(string(rules), -1) {
		if !known[match[1]] {
			t.Errorf("the rules select code %q, which no decision carries", match[1])
		}
	}
	for _, match := range regexp.MustCompile(`outcome="([a-z_]+)"`).FindAllStringSubmatch(string(rules), -1) {
		switch match[1] {
		case httpapi.DeliveryApplied, httpapi.DeliveryDuplicate, httpapi.DeliverySuperseded,
			httpapi.DeliveryAcknowledged, httpapi.DeliveryRefused, httpapi.DeliveryFailed:
		default:
			t.Errorf("the rules select outcome %q, which the intake never records", match[1])
		}
	}
}
