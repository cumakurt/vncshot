package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ManifestSignatureFilename is the detached ed25519 signature written next
// to the manifest when -sign-key is configured. The signature covers the
// exact manifest.json bytes as written.
const ManifestSignatureFilename = "manifest.sig"

// privateKeyPEMType and publicKeyPEMType are the PEM block types used for
// the signing key pair. PKCS#8/PKIX wrapping keeps the files loadable by any
// standard tool, not only by vncshot.
const (
	privateKeyPEMType = "PRIVATE KEY"
	publicKeyPEMType  = "PUBLIC KEY"
)

// LoadOrCreateSignKey returns the ed25519 private key stored at path. When
// the file does not exist, a new key pair is generated: the private key is
// written as PKCS#8 PEM with owner-only permissions, and the public key is
// written as SPKI PEM next to it at path+".pub". The second return value
// reports whether a new key was generated, so callers can print a notice.
func LoadOrCreateSignKey(path string) (ed25519.PrivateKey, bool, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		key, err := parseEd25519PrivateKey(data)
		if err != nil {
			return nil, false, fmt.Errorf("read signing key %s: %w", path, err)
		}
		return key, false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, fmt.Errorf("read signing key %s: %w", path, err)
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, fmt.Errorf("generate signing key: %w", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, false, fmt.Errorf("marshal signing key: %w", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: pkcs8})
	if err := os.WriteFile(path, privatePEM, 0o600); err != nil {
		return nil, false, fmt.Errorf("write signing key %s: %w", path, err)
	}
	// The explicit mode is subject to the process umask; the chmod below
	// makes the owner-only guarantee independent of it.
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, false, fmt.Errorf("restrict signing key permissions %s: %w", path, err)
	}

	publicPath := path + ".pub"
	spki, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, false, fmt.Errorf("marshal signing public key: %w", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: publicKeyPEMType, Bytes: spki})
	if err := os.WriteFile(publicPath, publicPEM, 0o644); err != nil {
		return nil, false, fmt.Errorf("write signing public key %s: %w", publicPath, err)
	}
	return privateKey, true, nil
}

// LoadSignPublicKey reads an ed25519 public key from a SPKI PEM file.
func LoadSignPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing public key %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("read signing public key %s: no PEM block found", path)
	}
	if block.Type != publicKeyPEMType {
		return nil, fmt.Errorf("read signing public key %s: unexpected PEM type %q", path, block.Type)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signing public key %s: %w", path, err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("read signing public key %s: key is %T, want ed25519", path, parsed)
	}
	return key, nil
}

// parseEd25519PrivateKey decodes a PKCS#8 PEM private key and requires it to
// be an ed25519 key, so a wrong key type fails loudly instead of at sign time.
func parseEd25519PrivateKey(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != privateKeyPEMType {
		return nil, fmt.Errorf("unexpected PEM type %q", block.Type)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is %T, want ed25519", parsed)
	}
	return key, nil
}

// SignManifest writes <runDir>/manifest.sig, the detached base64-encoded
// ed25519 signature over the exact manifest.json bytes as they are on disk.
// It must be called after WriteManifest.
func SignManifest(runDir string, key ed25519.PrivateKey) (string, error) {
	manifestPath := filepath.Join(runDir, ManifestFilename)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", fmt.Errorf("read manifest for signing %s: %w", manifestPath, err)
	}

	signature := ed25519.Sign(key, data)
	encoded := base64.StdEncoding.EncodeToString(signature) + "\n"

	path := filepath.Join(runDir, ManifestSignatureFilename)
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		return "", fmt.Errorf("write manifest signature %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return "", fmt.Errorf("restrict manifest signature permissions: %w", err)
	}
	return path, nil
}

// VerifySignedManifest verifies the detached manifest signature and then
// every artifact digest listed in the manifest. It is designed to run on any
// machine: nothing but the run directory and the public key is consulted.
// The first failure is returned with the artifact name, so an operator can
// tell exactly which file does not match. Extra files in the run directory
// (manifest.sig itself, for example) are not reported, because the manifest
// only guarantees the files it lists.
func VerifySignedManifest(runDir string, publicKey ed25519.PublicKey) error {
	manifestPath := filepath.Join(runDir, ManifestFilename)
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest %s: %w", manifestPath, err)
	}

	signaturePath := filepath.Join(runDir, ManifestSignatureFilename)
	signatureData, err := os.ReadFile(signaturePath)
	if err != nil {
		return fmt.Errorf("read manifest signature %s: %w", signaturePath, err)
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signatureData)))
	if err != nil {
		return fmt.Errorf("decode manifest signature %s: %w", signaturePath, err)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("verify manifest signature %s: signature is %d bytes, want %d",
			signaturePath, len(signature), ed25519.SignatureSize)
	}
	if !ed25519.Verify(publicKey, manifestData, signature) {
		return fmt.Errorf("verify manifest signature %s: signature does not match %s", signaturePath, manifestPath)
	}

	var manifest Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return fmt.Errorf("parse manifest %s: %w", manifestPath, err)
	}
	if manifest.Algorithm != manifestAlgorithm {
		return fmt.Errorf("verify manifest %s: unsupported algorithm %q", manifestPath, manifest.Algorithm)
	}

	for _, want := range manifest.Files {
		if err := verifyManifestEntry(runDir, want); err != nil {
			return err
		}
	}
	return nil
}

// verifyManifestEntry re-hashes one listed artifact and reports the first
// deviation: an unsafe path, a missing file or a digest mismatch.
func verifyManifestEntry(runDir string, want ManifestEntry) error {
	// Manifest paths are produced by hashRunDir as slash-separated relative
	// names; reject anything that could escape the run directory before the
	// path reaches the filesystem.
	if want.Path == "" || filepath.IsAbs(want.Path) ||
		filepath.Clean(want.Path) != want.Path || strings.HasPrefix(want.Path, "../") {
		return fmt.Errorf("verify manifest: unsafe artifact path %q", want.Path)
	}

	path := filepath.Join(runDir, filepath.FromSlash(want.Path))
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("verify manifest: missing file %s", want.Path)
		}
		return fmt.Errorf("verify manifest: stat %s: %w", want.Path, err)
	}
	got, err := hashFile(path, want.Path)
	if err != nil {
		return fmt.Errorf("verify manifest: %w", err)
	}
	if got.Size != want.Size || got.SHA256 != want.SHA256 {
		return fmt.Errorf("verify manifest: checksum mismatch for %s", want.Path)
	}
	return nil
}
