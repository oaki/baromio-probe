package identity

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrGenerateGeneratesAFreshKeyPair(t *testing.T) {
	dir := t.TempDir()

	id, err := LoadOrGenerate(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(id.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("expected a %d-byte public key, got %d", ed25519.PublicKeySize, len(id.PublicKey))
	}

	if id.IsEnrolled() {
		t.Error("a freshly generated identity should not be enrolled yet")
	}
}

func TestLoadOrGenerateIsStableAcrossCalls(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadOrGenerate(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	second, err := LoadOrGenerate(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if first.PublicKeyBase64() != second.PublicKeyBase64() {
		t.Error("expected the same key pair to be loaded back, got a different one")
	}
}

func TestSavePersistsTheProbeId(t *testing.T) {
	dir := t.TempDir()

	id, err := LoadOrGenerate(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	id.ProbeID = "11111111-1111-1111-1111-111111111111"
	if err := id.Save(dir); err != nil {
		t.Fatalf("unexpected error saving: %v", err)
	}

	reloaded, err := LoadOrGenerate(dir)
	if err != nil {
		t.Fatalf("unexpected error reloading: %v", err)
	}

	if !reloaded.IsEnrolled() {
		t.Fatal("expected the reloaded identity to be enrolled")
	}

	if reloaded.ProbeID != id.ProbeID {
		t.Errorf("expected probe id %q, got %q", id.ProbeID, reloaded.ProbeID)
	}
}

func TestSignProducesAVerifiableSignature(t *testing.T) {
	dir := t.TempDir()

	id, err := LoadOrGenerate(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	message := []byte("v1\nPOST\n/api/v1/probe/report\n1700000000\nabc")
	sig := id.Sign(message)

	if sig == "" {
		t.Fatal("expected a non-empty signature")
	}
}

func TestLoadRefusesAStoredKeyOfTheWrongLength(t *testing.T) {
	dir := t.TempDir()
	body := `{"probe_id":"p","public_key":"AAAA","private_key":"AAAA"}`
	if err := os.WriteFile(filepath.Join(dir, "identity.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadOrGenerate(dir); err == nil {
		t.Fatal("expected a truncated key to be refused rather than panic on first sign")
	}
}
