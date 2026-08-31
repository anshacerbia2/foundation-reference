package projection

import _ "embed"

// Schema is projection.membership, embedded by the package that owns it.
//
// go:embed cannot reach outside its own directory, and that constraint is the right shape
// here anyway: the migration command should not know where this repository keeps its DDL,
// only that the package which defines the projection also publishes it.
//
//go:embed schema.sql
var Schema string
