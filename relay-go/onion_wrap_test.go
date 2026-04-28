// onion_wrap_test.go — unit tests for the relay-key KEK wrap.
//
// loadOrCreateRelayKey persists the onion X25519 private key under
// either the legacy plaintext layout or the new wrapped layout.  The
// wrapped layout is gated on RELAY_KEY_KEK (or RELAY_KEY_KEK_FILE);
// without that, we fall back to plaintext + a stderr warning.  These
// tests pin the expected behaviour for each configuration so a
// regression couldn't silently downgrade a wrapped deployment to
// plaintext or vice versa.

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

// Helper: generate a fresh 32-byte KEK and return its base64url form.
func randomKek(t *testing.T) (raw []byte, b64url string) {
	t.Helper()
	raw = make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	b64url = base64.RawURLEncoding.EncodeToString(raw)
	return
}

func withEnv(t *testing.T, keyValues ...string) {
	t.Helper()
	if len(keyValues)%2 != 0 {
		t.Fatalf("withEnv: odd number of args")
	}
	for i := 0; i < len(keyValues); i += 2 {
		k, v := keyValues[i], keyValues[i+1]
		old, had := os.LookupEnv(k)
		if v == "" {
			os.Unsetenv(k)
		} else {
			os.Setenv(k, v)
		}
		t.Cleanup(func() {
			if had {
				os.Setenv(k, old)
			} else {
				os.Unsetenv(k)
			}
		})
	}
}

// ── 1. Without a KEK: plaintext layout on disk ─────────────────────────

func TestRelayKey_NoKekPersistsPlaintext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay_key.bin")
	withEnv(t, "RELAY_KEY_PATH", path,
		"RELAY_KEY_KEK", "",
		"RELAY_KEY_KEK_FILE", "")

	pub1, priv1, err := loadOrCreateRelayKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted key: %v", err)
	}
	if len(data) != 32 {
		t.Fatalf("plaintext key should be 32 bytes on disk, got %d", len(data))
	}
	if !bytes.Equal(data, priv1[:]) {
		t.Fatalf("on-disk bytes don't match returned priv")
	}

	// Reload — pub should match.
	pub2, _, err := loadOrCreateRelayKey()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !bytes.Equal(pub1[:], pub2[:]) {
		t.Fatalf("pub mismatch across reload")
	}
}

// ── 2. With RELAY_KEY_KEK: wrapped layout on disk ──────────────────────

func TestRelayKey_WithKekPersistsWrapped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay_key.bin")
	_, kekB64 := randomKek(t)
	withEnv(t, "RELAY_KEY_PATH", path,
		"RELAY_KEY_KEK", kekB64,
		"RELAY_KEY_KEK_FILE", "")

	pub1, priv1, err := loadOrCreateRelayKey()
	if err != nil {
		t.Fatalf("generate with KEK: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted key: %v", err)
	}
	if len(data) == 32 {
		t.Fatalf("expected wrapped key on disk, got plaintext 32 bytes")
	}
	if data[0] != relayKeyVersionWrapped {
		t.Fatalf("expected version byte 0x02, got 0x%02x", data[0])
	}
	// The plaintext scalar must NOT appear anywhere in the wrapped blob.
	if bytes.Contains(data, priv1[:]) {
		t.Fatalf("plaintext scalar leaked into wrapped blob")
	}

	// Reload with the same KEK should recover the same pub.
	pub2, _, err := loadOrCreateRelayKey()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !bytes.Equal(pub1[:], pub2[:]) {
		t.Fatalf("pub mismatch across reload")
	}
}

// ── 3. Reload with wrong KEK fails loudly ──────────────────────────────

func TestRelayKey_WrongKekRefusesLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay_key.bin")
	_, kek1 := randomKek(t)
	_, kek2 := randomKek(t)
	withEnv(t, "RELAY_KEY_PATH", path,
		"RELAY_KEY_KEK", kek1)

	if _, _, err := loadOrCreateRelayKey(); err != nil {
		t.Fatalf("initial load: %v", err)
	}

	// Swap the KEK — a rotation without re-wrapping must refuse.
	os.Setenv("RELAY_KEY_KEK", kek2)
	_, _, err := loadOrCreateRelayKey()
	if err == nil {
		t.Fatalf("expected unwrap failure with wrong KEK")
	}
}

// ── 4. Wrapped-on-disk + no KEK configured → refuse to start ───────────

func TestRelayKey_WrappedWithoutKekRefusesLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay_key.bin")
	_, kekB64 := randomKek(t)

	// First: write a wrapped key.
	withEnv(t, "RELAY_KEY_PATH", path, "RELAY_KEY_KEK", kekB64)
	if _, _, err := loadOrCreateRelayKey(); err != nil {
		t.Fatalf("initial load: %v", err)
	}
	// Then: unset the KEK and try to load again.
	os.Unsetenv("RELAY_KEY_KEK")
	_, _, err := loadOrCreateRelayKey()
	if err == nil {
		t.Fatalf("expected failure loading wrapped key without KEK")
	}
}

// ── 5. RELAY_KEY_KEK_FILE path also works ──────────────────────────────

func TestRelayKey_KekFileVariantPersistsWrapped(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "relay_key.bin")
	kekPath := filepath.Join(dir, "kek.bin")

	kekRaw, _ := randomKek(t)
	if err := os.WriteFile(kekPath, kekRaw, 0o600); err != nil {
		t.Fatalf("write kek file: %v", err)
	}
	withEnv(t, "RELAY_KEY_PATH", keyPath,
		"RELAY_KEY_KEK", "",
		"RELAY_KEY_KEK_FILE", kekPath)

	if _, _, err := loadOrCreateRelayKey(); err != nil {
		t.Fatalf("generate: %v", err)
	}
	data, _ := os.ReadFile(keyPath)
	if len(data) == 0 || data[0] != relayKeyVersionWrapped {
		t.Fatalf("expected wrapped format with KEK_FILE set; got %d bytes, ver=0x%02x",
			len(data), data[0])
	}
}

// ── 6. Bad RELAY_KEY_KEK (wrong length / not base64) fails loudly ──────

func TestRelayKey_BadKekEnvIsFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay_key.bin")
	withEnv(t, "RELAY_KEY_PATH", path, "RELAY_KEY_KEK", "!!! not base64 !!!")

	_, _, err := loadOrCreateRelayKey()
	if err == nil {
		t.Fatalf("expected failure for non-base64 KEK")
	}

	// Wrong-length decoded KEK.
	short := base64.RawURLEncoding.EncodeToString([]byte("too-short"))
	os.Setenv("RELAY_KEY_KEK", short)
	_, _, err = loadOrCreateRelayKey()
	if err == nil {
		t.Fatalf("expected failure for wrong-length KEK")
	}
}
