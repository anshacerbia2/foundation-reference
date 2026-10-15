package config

// Load reads process-wide state, so these do not run in parallel.

import (
	"os"
	"strings"
	"testing"
)

// required sets every variable without a default, after clearing the ambient REFERENCE_ ones: `make`
// loads .env, so a variable this helper forgets would be supplied by a developer's shell and absent
// in CI.
func required(t *testing.T) {
	t.Helper()
	for _, entry := range os.Environ() {
		if name, _, ok := strings.Cut(entry, "="); ok && strings.HasPrefix(name, "REFERENCE_") {
			t.Setenv(name, "")
		}
	}
	t.Setenv("REFERENCE_DATABASE_URL", "postgres://reference@localhost/reference")
	t.Setenv("REFERENCE_TOKEN_ISSUER", "https://issuer.example")
	t.Setenv("REFERENCE_JWKS_URL", "https://issuer.example/certs")
	t.Setenv("REFERENCE_DELIVERY_PRINCIPAL_ID", "55555555-5555-4555-8555-55555555550b")
}

func TestTheDeliveringWorkloadIsRead(t *testing.T) {
	required(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DeliveryPrincipal != "55555555-5555-4555-8555-55555555550b" {
		t.Errorf("the delivering workload read as %q", cfg.DeliveryPrincipal)
	}
}

// Without the workload the intake would admit nobody, and with a value that is not a principal_id it
// would admit nobody either; both are refused at startup, naming the variable.
func TestTheDeliveringWorkloadIsRequiredAndAPrincipalID(t *testing.T) {
	for _, value := range []string{"", "organization-control"} {
		required(t)
		t.Setenv("REFERENCE_DELIVERY_PRINCIPAL_ID", value)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "REFERENCE_DELIVERY_PRINCIPAL_ID") {
			t.Errorf("%q answered %v", value, err)
		}
	}
}
