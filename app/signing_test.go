package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// requireTestSignKey generates a key pair directly, because the generation
// path is covered by its own test.
func requireTestSignKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return privateKey
}

func prepareSignedRun(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	runDir := t.TempDir()
	writeRunFile(t, filepath.Join(runDir, "vncshot_report.json"), `{"results":[]}`)
	writeRunFile(t, filepath.Join(runDir, "vncshot_report.csv"), "ip,port\n10.0.0.1,5900\n")
	if _, err := WriteManifest(runDir); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	return runDir, requireTestSignKey(t)
}

func TestLoadOrCreateSignKeyGeneratesLoadableKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.pem")

	key, generated, err := LoadOrCreateSignKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateSignKey: %v", err)
	}
	if !generated {
		t.Fatal("first call should generate a key")
	}
	if len(key) != ed25519.PrivateKeySize {
		t.Fatalf("generated key size = %d, want %d", len(key), ed25519.PrivateKeySize)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat signing key: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("signing key mode = %o, want 600", mode)
	}

	publicPath := path + ".pub"
	publicInfo, err := os.Stat(publicPath)
	if err != nil {
		t.Fatalf("stat signing public key: %v", err)
	}
	if !publicInfo.Mode().IsRegular() {
		t.Error("public key is not a regular file")
	}

	// The generated pair must round-trip through the loaders.
	loaded, generatedAgain, err := LoadOrCreateSignKey(path)
	if err != nil {
		t.Fatalf("second LoadOrCreateSignKey: %v", err)
	}
	if generatedAgain {
		t.Error("second call generated a new key over an existing one")
	}
	if !loaded.Equal(key) {
		t.Error("loaded key differs from the generated key")
	}
	publicKey, err := LoadSignPublicKey(publicPath)
	if err != nil {
		t.Fatalf("LoadSignPublicKey: %v", err)
	}
	if !key.Public().(ed25519.PublicKey).Equal(publicKey) {
		t.Error("public key does not match the private key")
	}
}

func TestLoadOrCreateSignKeyRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(path, []byte("not a pem file"), 0o600); err != nil {
		t.Fatalf("write garbage key: %v", err)
	}
	if _, _, err := LoadOrCreateSignKey(path); err == nil {
		t.Error("LoadOrCreateSignKey accepted a non-PEM file")
	}
}

func TestLoadOrCreateSignKeyRejectsWrongKeyType(t *testing.T) {
	dir := t.TempDir()

	// A valid PKCS#8 key of the wrong type must be rejected instead of
	// failing later at signing time.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("marshal rsa key: %v", err)
	}
	path := filepath.Join(dir, "rsa.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		t.Fatalf("write rsa key: %v", err)
	}
	_, _, err = LoadOrCreateSignKey(path)
	if err == nil || !strings.Contains(err.Error(), "ed25519") {
		t.Errorf("LoadOrCreateSignKey error = %v, want an ed25519 type error", err)
	}
}

func TestSignManifestRoundtripVerifies(t *testing.T) {
	runDir, key := prepareSignedRun(t)

	sigPath, err := SignManifest(runDir, key)
	if err != nil {
		t.Fatalf("SignManifest: %v", err)
	}
	if sigPath != filepath.Join(runDir, ManifestSignatureFilename) {
		t.Errorf("signature path = %q, want %q", sigPath, filepath.Join(runDir, ManifestSignatureFilename))
	}
	info, err := os.Stat(sigPath)
	if err != nil {
		t.Fatalf("stat signature: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("signature mode = %o, want 600", mode)
	}

	if err := VerifySignedManifest(runDir, key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("VerifySignedManifest: %v", err)
	}
}

func TestVerifySignedManifestDetectsTamperedManifest(t *testing.T) {
	runDir, key := prepareSignedRun(t)
	if _, err := SignManifest(runDir, key); err != nil {
		t.Fatalf("SignManifest: %v", err)
	}

	// Tamper with the manifest bytes: any change after signing, however
	// small, must invalidate the signature.
	data, err := os.ReadFile(filepath.Join(runDir, ManifestFilename))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runDir, ManifestFilename), append(data, '\n'), 0o600); err != nil {
		t.Fatalf("rewrite manifest: %v", err)
	}
	publicKey := key.Public().(ed25519.PublicKey)
	err = VerifySignedManifest(runDir, publicKey)
	if err == nil {
		t.Fatal("VerifySignedManifest accepted a tampered manifest")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("error %q does not mention the signature", err)
	}
}

func TestVerifySignedManifestDetectsTamperedArtifact(t *testing.T) {
	runDir, key := prepareSignedRun(t)
	if _, err := SignManifest(runDir, key); err != nil {
		t.Fatalf("SignManifest: %v", err)
	}

	writeRunFile(t, filepath.Join(runDir, "vncshot_report.csv"), "ip,port\n10.0.0.99,5900\n")
	publicKey := key.Public().(ed25519.PublicKey)
	err := VerifySignedManifest(runDir, publicKey)
	if err == nil {
		t.Fatal("VerifySignedManifest accepted a tampered artifact")
	}
	if !strings.Contains(err.Error(), "vncshot_report.csv") {
		t.Errorf("error %q does not name the failing artifact", err)
	}
}

func TestVerifySignedManifestDetectsMissingArtifact(t *testing.T) {
	runDir, key := prepareSignedRun(t)
	if _, err := SignManifest(runDir, key); err != nil {
		t.Fatalf("SignManifest: %v", err)
	}

	if err := os.Remove(filepath.Join(runDir, "vncshot_report.csv")); err != nil {
		t.Fatalf("remove artifact: %v", err)
	}
	publicKey := key.Public().(ed25519.PublicKey)
	err := VerifySignedManifest(runDir, publicKey)
	if err == nil {
		t.Fatal("VerifySignedManifest accepted a missing artifact")
	}
	if !strings.Contains(err.Error(), "vncshot_report.csv") {
		t.Errorf("error %q does not name the missing artifact", err)
	}
}

func TestVerifySignedManifestRejectsMissingSignature(t *testing.T) {
	runDir, key := prepareSignedRun(t)
	if err := VerifySignedManifest(runDir, key.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("VerifySignedManifest accepted a run without a signature")
	}
}

func TestVerifySignedManifestRejectsUnsafeArtifactPath(t *testing.T) {
	runDir, key := prepareSignedRun(t)

	// Hand-craft a manifest whose entry escapes the run directory and sign
	// exactly those bytes, so the signature check passes and the path guard
	// is what rejects the manifest.
	manifest := Manifest{
		GeneratedAt: "2026-10-28T00:00:00Z",
		Algorithm:   "sha256",
		Root:        filepath.Base(runDir),
		Files:       []ManifestEntry{{Path: "../escape.txt", Size: 5, SHA256: strings.Repeat("0", 64)}},
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(runDir, ManifestFilename), data, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if _, err := SignManifest(runDir, key); err != nil {
		t.Fatalf("SignManifest: %v", err)
	}

	err = VerifySignedManifest(runDir, key.Public().(ed25519.PublicKey))
	if err == nil {
		t.Fatal("VerifySignedManifest accepted an unsafe artifact path")
	}
	if !strings.Contains(err.Error(), "../escape.txt") {
		t.Errorf("error %q does not name the unsafe path", err)
	}
}

func TestVerifySignedManifestRejectsWrongKey(t *testing.T) {
	runDir, key := prepareSignedRun(t)
	if _, err := SignManifest(runDir, key); err != nil {
		t.Fatalf("SignManifest: %v", err)
	}

	otherKey := requireTestSignKey(t)
	if err := VerifySignedManifest(runDir, otherKey.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("VerifySignedManifest accepted the wrong public key")
	}
}

// Re-hashing a signed run must not list the detached signature: it is
// written after the manifest, so it can never be part of its own file list.
func TestWriteManifestExcludesSignature(t *testing.T) {
	runDir, key := prepareSignedRun(t)
	if _, err := SignManifest(runDir, key); err != nil {
		t.Fatalf("SignManifest: %v", err)
	}

	if _, err := WriteManifest(runDir); err != nil {
		t.Fatalf("second WriteManifest: %v", err)
	}
	manifest, _ := readManifest(t, runDir)
	for _, entry := range manifest.Files {
		if entry.Path == ManifestSignatureFilename {
			t.Error("manifest lists its own signature")
		}
	}
	if err := VerifyManifest(runDir); err != nil {
		t.Errorf("VerifyManifest: %v", err)
	}
}

// A full session scan signs the finalized manifest and writes the SARIF
// report before the manifest, so the signed file list includes the SARIF
// artifact and the offline verification passes on the fresh run directory.
func TestSessionScanSignsManifestAndWritesSARIF(t *testing.T) {
	base := t.TempDir()
	ports := closedLocalPorts(t, 1)

	session, err := Prepare(Config{
		Target:         "127.0.0.1",
		Ports:          fmt.Sprintf("%d", ports[0]),
		ConnectTimeout: 200 * time.Millisecond,
		VNCTimeout:     200 * time.Millisecond,
		Workers:        1,
		OutDir:         base,
		OutDirExplicit: true,
		NoPDF:          true,
		Manifest:       true,
		SARIF:          "findings.sarif",
		SignKey:        requireTestSignKey(t),
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if session.SARIFPath != filepath.Join(session.RunDir, "findings.sarif") {
		t.Errorf("sarif path = %q, want it relative to the run directory", session.SARIFPath)
	}
	signKey := session.config.SignKey

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := session.Scan(ctx, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if out.SARIF != session.SARIFPath {
		t.Errorf("outcome sarif = %q, want %q", out.SARIF, session.SARIFPath)
	}
	if out.Signature != filepath.Join(session.RunDir, ManifestSignatureFilename) {
		t.Errorf("signature = %q, want it inside the run directory", out.Signature)
	}

	sarifData, err := os.ReadFile(out.SARIF)
	if err != nil {
		t.Fatalf("read sarif report: %v", err)
	}
	var sarif struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarifData, &sarif); err != nil {
		t.Fatalf("parse sarif report: %v", err)
	}
	if sarif.Version != "2.1.0" {
		t.Errorf("sarif version = %q, want 2.1.0", sarif.Version)
	}
	// Closed ports are not findings, so the clean scan must still be valid
	// SARIF with zero results.
	if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 0 {
		t.Errorf("clean scan produced %v, want one run with zero results", sarif.Runs)
	}

	if err := VerifySignedManifest(session.RunDir, signKey.Public().(ed25519.PublicKey)); err != nil {
		t.Errorf("VerifySignedManifest: %v", err)
	}
}
