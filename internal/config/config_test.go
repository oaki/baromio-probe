package config

import "testing"

func TestLoadRequiresAllow(t *testing.T) {
	t.Setenv("BAROMIO_ALLOW", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected an error when BAROMIO_ALLOW is unset")
	}
}

func TestLoadDefaultsUrlAndDataDir(t *testing.T) {
	t.Setenv("BAROMIO_ALLOW", "10.0.0.0/8")
	t.Setenv("BAROMIO_URL", "")
	t.Setenv("BAROMIO_DATA_DIR", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.URL != defaultURL {
		t.Errorf("expected default URL %q, got %q", defaultURL, cfg.URL)
	}

	if cfg.DataDir != "/var/lib/baromio-probe" {
		t.Errorf("expected default data dir, got %q", cfg.DataDir)
	}
}

func TestLoadTrimsTrailingSlashFromUrl(t *testing.T) {
	t.Setenv("BAROMIO_ALLOW", "10.0.0.0/8")
	t.Setenv("BAROMIO_URL", "https://example.com/")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.URL != "https://example.com" {
		t.Errorf("expected trailing slash trimmed, got %q", cfg.URL)
	}
}

func TestLoadReadsEnrollToken(t *testing.T) {
	t.Setenv("BAROMIO_ALLOW", "10.0.0.0/8")
	t.Setenv("BAROMIO_ENROLL_TOKEN", "secret-token")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.EnrollToken != "secret-token" {
		t.Errorf("expected enroll token to be read, got %q", cfg.EnrollToken)
	}
}
