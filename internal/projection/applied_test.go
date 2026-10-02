package projection

import (
	"testing"

	"github.com/anshacerbia2/foundation-platform/event"
)

// The subscription is what the producer delivers, so a type listed here that this consumer only
// acknowledges would be delivered for nothing, and a duplicate would say nothing new. Every applied
// type is one Apply acts on: the Membership and Tenant types and the repair.
func TestAppliedEventTypesAreTheTypesThisConsumerActsOn(t *testing.T) {
	seen := map[string]bool{}
	for _, eventType := range AppliedEventTypes() {
		if seen[string(eventType)] {
			t.Errorf("%s is listed twice", eventType)
		}
		seen[string(eventType)] = true
		if acknowledged[eventType] {
			t.Errorf("%s is acknowledged and not applied, so subscribing to it delivers nothing", eventType)
		}
		if _, err := event.ParseType(string(eventType)); err != nil {
			t.Errorf("%s is not a valid event type: %v", eventType, err)
		}
	}
	if len(seen) != 9 {
		t.Errorf("%d applied types, want the four Membership, four Tenant and the repair", len(seen))
	}
}
