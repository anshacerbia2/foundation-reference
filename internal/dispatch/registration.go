package dispatch

import (
	"context"
	"errors"
	"fmt"

	fdb "github.com/anshacerbia2/foundation-platform/db"
)

// ErrUnregistered means the dispatcher's consumer name is not an active consumer registered with
// organization-control.
var ErrUnregistered = errors.New("dispatch: the consumer name is not an active registered consumer")

// transactor is the one method the check needs. *fdb.Pool satisfies it.
type transactor interface {
	InTx(ctx context.Context, fn func(context.Context, fdb.Tx) error) error
}

// registeredStatement reads two columns organization-control grants the dispatch role for exactly
// this: consumer_id and retired_at of projection.consumer.
const registeredStatement = `SELECT EXISTS (SELECT 1 FROM projection.consumer
    WHERE consumer_id = $1 AND retired_at IS NULL)`

// CheckRegistered refuses a consumer name that organization-control has not registered, or has
// retired.
//
// DISPATCH_CONSUMER_NAME keys every delivery receipt, and the resolver reads receipts by the
// registered consumer_id. A one-character mismatch produced receipts no resolution would ever find,
// and it surfaced only when an incident could not be closed. Checked once at startup, the mismatch
// is a process that will not start, with the name in the error.
//
// A consumer retired while this runs is not re-checked. Its receipts stop counting at the resolver,
// which reads the active consumer, and a restart then refuses.
func CheckRegistered(ctx context.Context, tx transactor, consumer string) error {
	var active bool
	if err := tx.InTx(ctx, func(ctx context.Context, tx fdb.Tx) error {
		return tx.QueryRow(ctx, registeredStatement, consumer).Scan(&active)
	}); err != nil {
		return fmt.Errorf("dispatch: checking that %q is a registered consumer: %w", consumer, err)
	}
	if !active {
		return fmt.Errorf("%w: %q. It must equal the consumer_id registered with organization-control "+
			"and REFERENCE_CONSUMER_NAME, or every receipt this dispatcher writes is one no resolution reads",
			ErrUnregistered, consumer)
	}
	return nil
}
