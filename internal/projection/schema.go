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

// Rebuild drops the projection so it can be rebuilt from a snapshot.
//
// Separate from Schema and applied only when asked for. A projection's recovery is
// rebuild-from-snapshot rather than repair, so dropping it is legitimate -- but it is an operation
// somebody chooses, never a side effect of a migration run.
//
//go:embed rebuild.sql
var Rebuild string
