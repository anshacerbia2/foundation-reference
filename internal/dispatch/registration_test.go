package dispatch

// The dispatcher's startup check on its own consumer name. The statement's privileges are asserted
// in organization-control, which grants them (dispatch_role_integration_test.go), and the positive
// path runs in the system proof on every build: the dispatcher there starts only if its name is
// registered.

import (
	"context"
	"errors"
	"strings"
	"testing"

	fdb "github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/db/dbtest"
)

type transactionFunc func(context.Context, func(context.Context, fdb.Tx) error) error

func (f transactionFunc) InTx(ctx context.Context, fn func(context.Context, fdb.Tx) error) error {
	return f(ctx, fn)
}

func answering(tx *dbtest.Tx) transactionFunc {
	return func(ctx context.Context, fn func(context.Context, fdb.Tx) error) error { return fn(ctx, tx) }
}

func TestARegisteredConsumerNameIsAccepted(t *testing.T) {
	tx := &dbtest.Tx{RowValues: []any{true}}
	if err := CheckRegistered(context.Background(), answering(tx), "foundation-reference"); err != nil {
		t.Fatalf("a registered name was refused: %v", err)
	}
	calls := tx.Calls()
	if len(calls) != 1 || calls[0].Args[0] != "foundation-reference" {
		t.Errorf("the check asked about %v, want the configured name", calls)
	}
}

// The misspelt name is the case the check exists for: before it, the dispatcher started and wrote
// receipts under a name no resolution reads.
func TestAnUnregisteredConsumerNameRefusesToStart(t *testing.T) {
	err := CheckRegistered(context.Background(), answering(&dbtest.Tx{RowValues: []any{false}}), "foundation-referense")
	if !errors.Is(err, ErrUnregistered) {
		t.Fatalf("an unregistered name was accepted, or refused for the wrong reason: %v", err)
	}
	if !strings.Contains(err.Error(), "foundation-referense") {
		t.Errorf("the refusal does not name the value an operator has to fix: %v", err)
	}
}

// A database that cannot answer is not an unregistered name, and must not be reported as one.
func TestAFailedCheckIsNotReportedAsUnregistered(t *testing.T) {
	failure := errors.New("permission denied for table consumer")
	err := CheckRegistered(context.Background(), transactionFunc(
		func(context.Context, func(context.Context, fdb.Tx) error) error { return failure }), "foundation-reference")
	if !errors.Is(err, failure) || errors.Is(err, ErrUnregistered) {
		t.Errorf("a failed check reported %v", err)
	}
}
