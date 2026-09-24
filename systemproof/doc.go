// Package systemproof runs Proof A across real process boundaries.
//
// Every other suite in the estate proves one side at a time. organization-control proves that a
// replay produces evidence and that the resolver closes an incident only on it; this repository
// proves that the consumer refuses under the producer's debt and serves once it clears. Neither
// can see the seam between them -- the frontier's wire format, the delivery endpoint's contract,
// the configuration each side holds about the other, and whether a state change on one side
// actually reaches a decision on the other. Component suites stay green while that seam is broken.
//
// So this runs the real system: organization-control built from an exact pinned revision, this
// repository's consumer, dispatcher and bootstrap, a token issuer, and PostgreSQL. The only
// component that is not production code is a proxy in front of the consumer, and it exists because
// the state under test cannot be produced any other way (see proof_test.go).
//
// The proof is behind the `systemproof` build tag. It builds binaries, creates databases and binds
// ports, which is not something `go test ./...` should do as a side effect.
package systemproof
