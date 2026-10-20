package projection_test

import (
	"errors"
	"testing"

	"github.com/anshacerbia2/foundation-reference/internal/projection"
)

// The report is what the consumer sends to organization-control's reconcile route: every active
// Membership it holds, at the position they correspond to. A withdrawn one is not reported, because the
// route compares the active set; and a consumer that has not bootstrapped reports nothing, because it
// holds no copy to compare.
func TestTheReportStatesTheActiveMembershipsAtTheirMark(t *testing.T) {
	projector, _, ctx, name := fixtureNamed(t)

	if _, err := projector.Report(ctx); !errors.Is(err, projection.ErrNotBootstrapped) {
		t.Fatalf("a consumer that never bootstrapped reported (%v), want ErrNotBootstrapped", err)
	}

	held, withdrawn := newSubject(t), newSubject(t)
	if err := projector.Seed(ctx, []projection.Seeded{{
		MembershipID: held.membership, TenantID: held.tenant, PrincipalID: held.principal,
		Status: projection.Active, Version: 3, TenantStatus: "active", TenantSecurityVersion: 1, TenantVersion: 1,
	}}, 7000, true); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	report, err := projector.Report(ctx)
	if err != nil {
		t.Fatalf("Report after the bootstrap: %v", err)
	}
	if report.ConsumerID != name || report.Mark != 7000 {
		t.Errorf("the report names %q at %d, want %q at the snapshot mark 7000", report.ConsumerID, report.Mark, name)
	}

	grant := granted(t, withdrawn, 1)
	grant.StreamPosition = 7001
	revoke := revoked(t, withdrawn, 2)
	revoke.StreamPosition = 7002
	if _, err := projector.Apply(ctx, grant); err != nil {
		t.Fatalf("granting: %v", err)
	}
	if _, err := projector.Apply(ctx, revoke); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	report, err = projector.Report(ctx)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if report.Mark != 7002 {
		t.Errorf("the report is at %d, want the highest applied position 7002", report.Mark)
	}
	// The table is shared with the other tests' consumers, so only these two rows are asserted.
	versions := map[string]int64{}
	for _, row := range report.Rows {
		versions[row.MembershipID] = row.MembershipVersion
	}
	if versions[held.membership.String()] != 3 {
		t.Errorf("the held Membership is reported at version %d, want 3", versions[held.membership.String()])
	}
	if _, reported := versions[withdrawn.membership.String()]; reported {
		t.Error("a revoked Membership was reported as held")
	}
}
