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

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/event"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/foundation-reference/internal/projection"
)

var tenantPositions int64 = 10_000

// tenantEvent is a Tenant event whose tenant_version equals its security version, which is what a Tenant
// whose every transition was a security one carries.
func tenantEvent(t *testing.T, tenant id.UUID, typ event.Type, status string, securityVersion int64) event.Envelope {
	t.Helper()
	return tenantEventAt(t, tenant, typ, status, securityVersion, securityVersion)
}

// tenantEventAt names both versions, for the cases where they differ.
func tenantEventAt(t *testing.T, tenant id.UUID, typ event.Type, status string,
	securityVersion, version int64) event.Envelope {
	t.Helper()
	envelope, err := event.New(source, typ, time.Now().UTC(), projection.TenantPayload{
		TenantID: tenant, TenantStatus: status, TenantSecurityVersion: securityVersion, TenantVersion: version,
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
		Status: projection.Active, Version: 1, TenantStatus: "suspended", TenantSecurityVersion: 5, TenantVersion: 5,
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
		// Without tenant_version an event cannot be ordered against one with the same security version.
		"no tenant_version": tenantEventAt(t, newID(t), projection.TenantSuspended, "suspended", 2, 0),
	} {
		if _, err := projector.Apply(ctx, envelope); !errors.Is(err, projection.ErrMalformed) {
			t.Errorf("%s: Apply returned %v, want ErrMalformed", name, err)
		}
	}
}

// Activation moves tenant_version and leaves the security version where it was, so the security version
// alone cannot order it against the provisioning state before it. Ordered by it alone, a snapshot that
// seeded the provisioning Tenant discarded the activation that followed, and every member stayed
// refused. tenant_version breaks the tie, and an older state with the same security version is still
// discarded.
func TestAnActivationWithTheSameSecurityVersionIsOrderedByTenantVersion(t *testing.T) {
	projector, _, ctx := fixture(t)
	s := newSubject(t)

	if err := projector.Seed(ctx, []projection.Seeded{{
		MembershipID: s.membership, TenantID: s.tenant, PrincipalID: s.principal,
		Status: projection.Active, Version: 1, TenantStatus: "provisioning", TenantSecurityVersion: 1, TenantVersion: 2,
	}}, 6000, true); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if _, err := projector.Lookup(ctx, s.tenant, s.principal); !errors.Is(err, projection.ErrTenantInactive) {
		t.Fatalf("a member of a provisioning tenant is not refused: %v", err)
	}

	outcome, err := projector.Apply(ctx, tenantEventAt(t, s.tenant, projection.TenantActivated, "active", 1, 3))
	if err != nil {
		t.Fatalf("activating: %v", err)
	}
	if !outcome.Applied {
		t.Fatalf("the activation was not applied over the provisioning state with the same security version: %+v",
			outcome)
	}
	if _, err := projector.Lookup(ctx, s.tenant, s.principal); err != nil {
		t.Errorf("the member is refused after the tenant was activated: %v", err)
	}

	// The provisioning state again, delivered late: same security version, older tenant_version.
	late, err := projector.Apply(ctx, tenantEventAt(t, s.tenant, projection.TenantActivated, "provisioning", 1, 2))
	if err != nil {
		t.Fatalf("delivering the older state: %v", err)
	}
	if !late.Superseded {
		t.Errorf("an older state with the same security version was applied: %+v", late)
	}
	if _, err := projector.Lookup(ctx, s.tenant, s.principal); err != nil {
		t.Errorf("a late, older state closed an active tenant: %v", err)
	}
}

// A restore to an older point moves every Tenant's version and security version by 10^9 before the
// authority serves, and republishes each withdrawn Tenant at its new versions (ADR-ORG-003 §5.5,
// TDD-organization-control-002 §After a Restore to an Older Point). The consumer applies a higher
// version and checks no gap, so the jump is applied like any later version; the next transition after
// it is applied; and an event from before the restore, delivered late, is discarded.
func TestARestoreBumpOfTenToTheNinthIsApplied(t *testing.T) {
	const margin int64 = 1_000_000_000 // organization-control's restore.Margin
	projector, pool, ctx := fixture(t)
	s := newSubject(t)

	// Before the restore the consumer applied a suspension and a restoration the restore then lost:
	// it holds the Tenant active at (5, 7). Authority is back at its backup, suspended at (3, 5).
	if _, err := projector.Apply(ctx, tenantEventAt(t, s.tenant, projection.TenantActivated, "active", 1, 1)); err != nil {
		t.Fatalf("activating: %v", err)
	}
	grantIn(t, projector, ctx, s)
	if _, err := projector.Apply(ctx, tenantEventAt(t, s.tenant, projection.TenantRestored, "active", 5, 7)); err != nil {
		t.Fatalf("applying the state the restore lost: %v", err)
	}

	// Without the bump, authority's next suspension would carry (4, 6) and be discarded here.
	unbumped, err := projector.Apply(ctx, tenantEventAt(t, s.tenant, projection.TenantSuspended, "suspended", 4, 6))
	if err != nil {
		t.Fatalf("delivering an unbumped suspension: %v", err)
	}
	if !unbumped.Superseded {
		t.Fatalf("the premise does not hold: an unbumped suspension below the held state was applied: %+v", unbumped)
	}

	// The bump republishes the suspended Tenant at (3+10^9, 5+10^9).
	bumped, err := projector.Apply(ctx, tenantEventAt(t, s.tenant, projection.TenantSuspended, "suspended",
		3+margin, 5+margin))
	if err != nil {
		t.Fatalf("delivering the bumped suspension: %v", err)
	}
	if !bumped.Applied {
		t.Fatalf("a suspension bumped by 10^9 was not applied: %+v", bumped)
	}
	if _, err := projector.Lookup(ctx, s.tenant, s.principal); !errors.Is(err, projection.ErrTenantInactive) {
		t.Fatalf("a member is served after the bumped suspension: %v", err)
	}

	// The next transition after the bump.
	next, err := projector.Apply(ctx, tenantEventAt(t, s.tenant, projection.TenantRestored, "active", 4+margin, 6+margin))
	if err != nil || !next.Applied {
		t.Fatalf("the restoration after the bump: outcome %+v, error %v; want applied", next, err)
	}
	if _, err := projector.Lookup(ctx, s.tenant, s.principal); err != nil {
		t.Errorf("the member is refused after the restoration that followed the bump: %v", err)
	}

	// A pre-restore event, delivered late, is below the bump and discarded.
	late, err := projector.Apply(ctx, tenantEventAt(t, s.tenant, projection.TenantSuspended, "suspended", 6, 8))
	if err != nil {
		t.Fatalf("delivering the late pre-restore event: %v", err)
	}
	if !late.Superseded {
		t.Errorf("a pre-restore event was applied over the bumped state: %+v", late)
	}

	var held struct{ security, version int64 }
	if err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT tenant_security_version, tenant_version FROM projection.tenant
		    WHERE tenant_id = $1`, s.tenant.String()).Scan(&held.security, &held.version)
	}); err != nil {
		t.Fatalf("reading the tenant: %v", err)
	}
	if held.security != 4+margin || held.version != 6+margin {
		t.Errorf("the tenant holds (%d, %d), want (%d, %d)", held.security, held.version, 4+margin, 6+margin)
	}
}

// Every version column is a bigint, so a margin of 10^9 on a version that is already large, applied
// more than once, cannot overflow: an integer column would stop at 2^31-1, two bumps away.
func TestEveryVersionColumnIsABigint(t *testing.T) {
	_, pool, ctx := fixture(t)
	want := map[string]bool{
		"membership.membership_version":      true,
		"membership.tenant_security_version": true,
		"tenant.tenant_security_version":     true,
		"tenant.tenant_version":              true,
	}
	if err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `SELECT table_name || '.' || column_name, data_type
		    FROM information_schema.columns
		   WHERE table_schema = 'projection' AND column_name LIKE '%version'`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var column, dataType string
			if err := rows.Scan(&column, &dataType); err != nil {
				return err
			}
			if dataType != "bigint" {
				t.Errorf("projection.%s is %s, want bigint", column, dataType)
			}
			delete(want, column)
		}
		return rows.Err()
	}); err != nil {
		t.Fatalf("reading the catalog: %v", err)
	}
	for column := range want {
		t.Errorf("projection.%s was not found", column)
	}
}
