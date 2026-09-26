package projection_test

// The Tenant's state, against a real PostgreSQL.
//
// The authority's own check refuses every member of a Tenant that is not active. Until this, the
// consumer never saw a Tenant event -- it refused them as unknown, so they dead-lettered -- and a
// suspended Tenant's members were served here while the authority refused them. These cases hold the
// consumer to the authority's answer.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/event"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/foundation-reference/internal/projection"
)

var tenantPositions int64 = 10_000

func tenantEvent(t *testing.T, tenant id.UUID, typ event.Type, status string, securityVersion int64) event.Envelope {
	t.Helper()
	envelope, err := event.New(source, typ, time.Now().UTC(), projection.TenantPayload{
		TenantID: tenant, TenantStatus: status, TenantSecurityVersion: securityVersion,
	})
	if err != nil {
		t.Fatalf("building a tenant envelope: %v", err)
	}
	tenantPositions++
	envelope.StreamPosition = tenantPositions
	return envelope
}

// activateTenant delivers the Tenant's activation, which the producer publishes before any
// Membership in the Tenant can exist.
func activateTenant(t *testing.T, projector *projection.Projector, ctx context.Context, tenant id.UUID) {
	t.Helper()
	if _, err := projector.Apply(ctx, tenantEvent(t, tenant, projection.TenantActivated, "active", 1)); err != nil {
		t.Fatalf("activating tenant %s: %v", tenant, err)
	}
}

func grantIn(t *testing.T, projector *projection.Projector, ctx context.Context, s subject) {
	t.Helper()
	if _, err := projector.Apply(ctx, granted(t, s, 1)); err != nil {
		t.Fatalf("granting: %v", err)
	}
}

// A suspension refuses every member, and a restoration lifts it -- the round trip the snapshot's old
// shortcut broke, because it wrote the suspension onto the membership rows and nothing restored them.
func TestATenantSuspensionRefusesItsMembersAndARestorationLiftsIt(t *testing.T) {
	projector, _, ctx := fixture(t)
	s := newSubject(t)
	activateTenant(t, projector, ctx, s.tenant)
	grantIn(t, projector, ctx, s)

	if _, err := projector.Lookup(ctx, s.tenant, s.principal); err != nil {
		t.Fatalf("an active member of an active tenant is refused: %v", err)
	}

	if _, err := projector.Apply(ctx, tenantEvent(t, s.tenant, projection.TenantSuspended, "suspended", 2)); err != nil {
		t.Fatalf("suspending: %v", err)
	}
	_, err := projector.Lookup(ctx, s.tenant, s.principal)
	if !errors.Is(err, projection.ErrTenantInactive) || !strings.Contains(err.Error(), "suspended") {
		t.Fatalf("Lookup returned %v for a member of a suspended tenant, want ErrTenantInactive naming it", err)
	}

	if _, err := projector.Apply(ctx, tenantEvent(t, s.tenant, projection.TenantRestored, "active", 3)); err != nil {
		t.Fatalf("restoring: %v", err)
	}
	if _, err := projector.Lookup(ctx, s.tenant, s.principal); err != nil {
		t.Errorf("the member is still refused after the tenant was restored: %v", err)
	}
}

// Offboarding and retirement refuse too. Offboarding publishes tenant.security.suspended with the
// status "offboarding", and the refusal names the status rather than the event type.
func TestOffboardingAndRetirementRefuseEveryMember(t *testing.T) {
	projector, _, ctx := fixture(t)
	s := newSubject(t)
	activateTenant(t, projector, ctx, s.tenant)
	grantIn(t, projector, ctx, s)

	if _, err := projector.Apply(ctx, tenantEvent(t, s.tenant, projection.TenantSuspended, "offboarding", 2)); err != nil {
		t.Fatalf("offboarding: %v", err)
	}
	if _, err := projector.Lookup(ctx, s.tenant, s.principal); !errors.Is(err, projection.ErrTenantInactive) ||
		!strings.Contains(err.Error(), "offboarding") {
		t.Errorf("Lookup returned %v during offboarding, want ErrTenantInactive naming offboarding", err)
	}

	if _, err := projector.Apply(ctx, tenantEvent(t, s.tenant, projection.TenantRetired, "retired", 3)); err != nil {
		t.Fatalf("retiring: %v", err)
	}
	if _, err := projector.Lookup(ctx, s.tenant, s.principal); !errors.Is(err, projection.ErrTenantInactive) {
		t.Errorf("Lookup returned %v for a retired tenant, want ErrTenantInactive", err)
	}
}

// The security version orders Tenant events, not delivery order. A restoration that arrives after
// the suspension it predates must not reopen the Tenant.
func TestAnOlderTenantEventDoesNotUndoANewerOne(t *testing.T) {
	projector, _, ctx := fixture(t)
	s := newSubject(t)
	activateTenant(t, projector, ctx, s.tenant)
	grantIn(t, projector, ctx, s)

	if _, err := projector.Apply(ctx, tenantEvent(t, s.tenant, projection.TenantSuspended, "suspended", 4)); err != nil {
		t.Fatalf("suspending at version 4: %v", err)
	}
	outcome, err := projector.Apply(ctx, tenantEvent(t, s.tenant, projection.TenantRestored, "active", 3))
	if err != nil {
		t.Fatalf("delivering the older restoration: %v", err)
	}
	if !outcome.Superseded {
		t.Errorf("an older restoration was applied: %+v", outcome)
	}
	if _, err := projector.Lookup(ctx, s.tenant, s.principal); !errors.Is(err, projection.ErrTenantInactive) {
		t.Errorf("a late, older restoration reopened a suspended tenant: %v", err)
	}
}

// A snapshot seeds the Tenant's state beside the membership, and a later Tenant event moves it. The
// membership keeps its own status: seeded active here, it is served once the Tenant is restored.
func TestASnapshotSeedsTheTenantAndALaterRestorationLiftsIt(t *testing.T) {
	projector, _, ctx := fixture(t)
	s := newSubject(t)

	if err := projector.Seed(ctx, []projection.Seeded{{
		MembershipID: s.membership, TenantID: s.tenant, PrincipalID: s.principal,
		Status: projection.Active, Version: 1, TenantStatus: "suspended", TenantSecurityVersion: 5,
	}}, 5000, true); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if _, err := projector.Lookup(ctx, s.tenant, s.principal); !errors.Is(err, projection.ErrTenantInactive) {
		t.Fatalf("a member of a tenant seeded as suspended is not refused: %v", err)
	}

	if _, err := projector.Apply(ctx, tenantEvent(t, s.tenant, projection.TenantRestored, "active", 6)); err != nil {
		t.Fatalf("restoring: %v", err)
	}
	if _, err := projector.Lookup(ctx, s.tenant, s.principal); err != nil {
		t.Errorf("the member is still refused after the seeded tenant was restored: %v", err)
	}
}

// An active membership whose Tenant has not been projected is refused: absence is no positive
// authority, for a Tenant as for a membership.
func TestAMemberOfAnUnprojectedTenantIsRefused(t *testing.T) {
	projector, _, ctx := fixture(t)
	s := newSubject(t)
	grantIn(t, projector, ctx, s)

	if _, err := projector.Lookup(ctx, s.tenant, s.principal); !errors.Is(err, projection.ErrTenantNotProjected) {
		t.Errorf("Lookup returned %v with no tenant state, want ErrTenantNotProjected", err)
	}
}

// The producer's events this consumer does not act on are acknowledged: nothing is applied and the
// watermark moves. Before, each was refused as unknown and dead-lettered, never to be closed.
func TestAnEventThisConsumerDoesNotActOnIsAcknowledged(t *testing.T) {
	projector, _, ctx := fixture(t)

	for _, typ := range []event.Type{
		"com.scnehaux.organization.workspace.lifecycle.created",
		"com.scnehaux.organization.membership.invitation.accepted",
		"com.scnehaux.organization.organization.registry.suspended",
		"com.scnehaux.organization.tenant.offboarding.frozen",
		"com.scnehaux.organization.tenant.lifecycle.requested",
	} {
		envelope := tenantEvent(t, newID(t), projection.TenantActivated, "active", 1)
		envelope.Type = typ
		outcome, err := projector.Apply(ctx, envelope)
		if err != nil {
			t.Errorf("%s was refused: %v", typ, err)
			continue
		}
		if !outcome.Acknowledged || outcome.Applied {
			t.Errorf("%s: outcome %+v, want acknowledged and nothing applied", typ, outcome)
		}
	}
}

// A Tenant event missing its status or version is malformed, not applied as something else.
func TestAMalformedTenantEventIsRefused(t *testing.T) {
	projector, _, ctx := fixture(t)
	for name, envelope := range map[string]event.Envelope{
		"no status":  tenantEvent(t, newID(t), projection.TenantSuspended, "", 2),
		"no version": tenantEvent(t, newID(t), projection.TenantSuspended, "suspended", 0),
		"no tenant":  tenantEvent(t, id.UUID{}, projection.TenantSuspended, "suspended", 2),
	} {
		if _, err := projector.Apply(ctx, envelope); !errors.Is(err, projection.ErrMalformed) {
			t.Errorf("%s: Apply returned %v, want ErrMalformed", name, err)
		}
	}
}
