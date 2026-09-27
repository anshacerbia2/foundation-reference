// Package telemetry is the consumer's half of organization-control's ROADMAP item 14: how often and
// why this consumer refuses, what its intake did with each delivery, and how old its projection is
// against its budget. The alert rules in deploy/alerts read these.
package telemetry

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/anshacerbia2/foundation-reference/internal/httpapi"
)

// Instrument is one metric: its OpenTelemetry name, unit and kind.
type Instrument struct {
	Name    string
	Unit    string
	Counter bool
}

// PrometheusName is the series a Collector's Prometheus exporter produces: dots to underscores, a
// seconds unit to _seconds, and a counter to _total. The alert rules read these, and a test holds
// the two together.
func (i Instrument) PrometheusName() string {
	name := strings.ReplaceAll(i.Name, ".", "_")
	if i.Unit == "s" {
		name += "_seconds"
	}
	if i.Counter {
		name += "_total"
	}
	return name
}

var (
	Decisions     = Instrument{"reference.enforcement.decisions", "{decision}", true}
	Deliveries    = Instrument{"reference.deliveries", "{delivery}", true}
	ProjectionAge = Instrument{"reference.projection.age", "s", false}
	MaxAge        = Instrument{"reference.projection.max_age", "s", false}
	Instruments   = []Instrument{Decisions, Deliveries, ProjectionAge, MaxAge}
)

const instrumentationName = "github.com/anshacerbia2/foundation-reference/internal/telemetry"

// ager is what the age gauge reads. The projector satisfies it.
type ager interface {
	Age(ctx context.Context) (time.Duration, error)
}

// Metrics implements httpapi.Metrics on OpenTelemetry.
type Metrics struct {
	decisions  metric.Int64Counter
	deliveries metric.Int64Counter
	identity   []attribute.KeyValue
}

var _ httpapi.Metrics = (*Metrics)(nil)

// New registers the instruments on provider. maxAge is the configured projection budget
// (REFERENCE_MAX_PROJECTION_AGE), exported beside the age so an alert compares the two without a
// threshold copied into a rule file.
func New(provider metric.MeterProvider, projection ager, maxAge time.Duration, deployable, system string) (*Metrics, error) {
	if provider == nil {
		return nil, errors.New("telemetry: a meter provider is required")
	}
	if projection == nil {
		return nil, errors.New("telemetry: a projection is required")
	}
	meter := provider.Meter(instrumentationName)
	decisions, err := meter.Int64Counter(Decisions.Name, metric.WithUnit(Decisions.Unit))
	if err != nil {
		return nil, err
	}
	deliveries, err := meter.Int64Counter(Deliveries.Name, metric.WithUnit(Deliveries.Unit))
	if err != nil {
		return nil, err
	}
	age, err := meter.Float64ObservableGauge(ProjectionAge.Name, metric.WithUnit(ProjectionAge.Unit))
	if err != nil {
		return nil, err
	}
	budget, err := meter.Float64ObservableGauge(MaxAge.Name, metric.WithUnit(MaxAge.Unit))
	if err != nil {
		return nil, err
	}

	identity := []attribute.KeyValue{attribute.String("deployable", deployable), attribute.String("system", system)}
	_, err = meter.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		o.ObserveFloat64(budget, maxAge.Seconds(), metric.WithAttributes(identity...))
		// A cold or unbootstrapped projection has no age, and none is observed: its refusals are
		// counted as not_bootstrapped, and a zero age would read as perfectly fresh.
		if current, err := projection.Age(ctx); err == nil {
			o.ObserveFloat64(age, current.Seconds(), metric.WithAttributes(identity...))
		}
		return nil
	}, age, budget)
	if err != nil {
		return nil, err
	}
	return &Metrics{decisions: decisions, deliveries: deliveries, identity: identity}, nil
}

// Decision counts one enforcement answer.
func (m *Metrics) Decision(ctx context.Context, class httpapi.Class, decision httpapi.Decision) {
	m.decisions.Add(ctx, 1, metric.WithAttributes(append(append([]attribute.KeyValue{}, m.identity...),
		attribute.String("class", string(class)),
		attribute.String("allowed", strconv.FormatBool(decision.Allow)),
		attribute.String("code", decision.Code))...))
}

// Delivery counts one intake outcome.
func (m *Metrics) Delivery(ctx context.Context, outcome string) {
	m.deliveries.Add(ctx, 1, metric.WithAttributes(append(append([]attribute.KeyValue{}, m.identity...),
		attribute.String("outcome", outcome))...))
}
