// Package identity manages the Probe's Ed25519 key pair and server-assigned
// id (ADR-0054). The private key is generated locally and never leaves this
// machine - only the public key is sent, once, on enrollment.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const fileName = "identity.json"

// Identity is the Probe's durable identity: its Ed25519 key pair, and the
// id Baromio assigned on enrollment (empty until enrolled).
type Identity struct {
	ProbeID    string             `json:"probe_id"`
	PublicKey  ed25519.PublicKey  `json:"-"`
	PrivateKey ed25519.PrivateKey `json:"-"`
}

type onDisk struct {
	ProbeID    string `json:"probe_id"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

// LoadOrGenerate reads the Probe's identity from dataDir, generating and
// persisting a fresh key pair if none exists yet. A restarted container
// without its data volume loses this and needs a new Enrollment Token
// (docs/design-plans/2026-10-05-private-probe.md §7.4).
func LoadOrGenerate(dataDir string) (*Identity, error) {
	path := filepath.Join(dataDir, fileName)

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return generate(dataDir)
	}
	if err != nil {
		return nil, fmt.Errorf("reading identity file: %w", err)
	}

	var stored onDisk
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("parsing identity file: %w", err)
	}

	pub, err := base64.StdEncoding.DecodeString(stored.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decoding stored public key: %w", err)
	}

	priv, err := base64.StdEncoding.DecodeString(stored.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decoding stored private key: %w", err)
	}

	return &Identity{
		ProbeID:    stored.ProbeID,
		PublicKey:  ed25519.PublicKey(pub),
		PrivateKey: ed25519.PrivateKey(priv),
	}, nil
}

func generate(dataDir string) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating key pair: %w", err)
	}

	identity := &Identity{PublicKey: pub, PrivateKey: priv}

	if err := identity.Save(dataDir); err != nil {
		return nil, err
	}

	return identity, nil
}

// IsEnrolled reports whether this identity has already been assigned a
// ProbeID by Baromio.
func (i *Identity) IsEnrolled() bool {
	return i.ProbeID != ""
}

// PublicKeyBase64 is the value sent as `public_key` on enroll.
func (i *Identity) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(i.PublicKey)
}

// Sign returns the base64-encoded Ed25519 signature over message, the value
// sent as the X-Baromio-Signature header.
func (i *Identity) Sign(message []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(i.PrivateKey, message))
}

// Save persists the identity to dataDir, mode 0600 - this file is the
// Probe's entire credential, equivalent to a private key on disk.
func (i *Identity) Save(dataDir string) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("creating data dir: %w", err)
	}

	stored := onDisk{
		ProbeID:    i.ProbeID,
		PublicKey:  base64.StdEncoding.EncodeToString(i.PublicKey),
		PrivateKey: base64.StdEncoding.EncodeToString(i.PrivateKey),
	}

	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding identity: %w", err)
	}

	path := filepath.Join(dataDir, fileName)
	tmp := path + ".tmp"

	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("writing identity file: %w", err)
	}

	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("finalizing identity file: %w", err)
	}

	return nil
}
