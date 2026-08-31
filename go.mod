// Reference consumer for the Scnehaux estate: the deployable that proves an authority
// change in organization-control reaches enforcement in another process.
//
// It is a separate module on purpose. A consumer living inside organization-control, or
// inside a BFF that ships with a UI, cannot demonstrate cross-product enforcement -- the
// process boundary is the property under test.
module github.com/anshacerbia2/foundation-reference

// The language floor matches foundation-platform rather than the toolchain CI builds with,
// the same way the two control repositories state it.
go 1.25.0

require github.com/anshacerbia2/foundation-platform v0.2.2

require (
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.10.0 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/otel v1.38.0 // indirect
	go.opentelemetry.io/otel/metric v1.38.0 // indirect
	go.opentelemetry.io/otel/trace v1.38.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/text v0.39.0 // indirect
)
