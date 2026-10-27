package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// ManifestFilename is the checksum manifest written inside a run directory.
const ManifestFilename = "manifest.json"

const manifestAlgorithm = "sha256"

// Manifest records the digest of every artifact in a run directory.
type Manifest struct {
	GeneratedAt string          `json:"generated_at"`
	Algorithm   string          `json:"algorithm"`
	Root        string          `json:"root"`
	Files       []ManifestEntry `json:"files"`
}

// ManifestEntry is the digest of one file, relative to the manifest root.
type ManifestEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// WriteManifest hashes every regular file in runDir and writes
// <runDir>/manifest.json. The manifest excludes itself, so calling it again
// produces the same file list. The file is owner-readable only because the
// run directory can hold captured desktops and weak credentials.
func WriteManifest(runDir string) (string, error) {
	info, err := os.Stat(runDir)
	if err != nil {
		return "", fmt.Errorf("read run directory %s: %w", runDir, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("read run directory %s: not a directory", runDir)
	}

	entries, err := hashRunDir(runDir)
	if err != nil {
		return "", err
	}

	manifest := Manifest{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Algorithm:   manifestAlgorithm,
		Root:        filepath.Base(filepath.Clean(runDir)),
		Files:       entries,
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal manifest: %w", err)
	}
	data = append(data, '\n')

	path := filepath.Join(runDir, ManifestFilename)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("write manifest %s: %w", path, err)
	}
	// The explicit mode is subject to the process umask; the chmod below
	// makes the owner-only guarantee independent of it.
	if err := os.Chmod(path, 0o600); err != nil {
		return "", fmt.Errorf("restrict manifest permissions: %w", err)
	}
	return path, nil
}

// VerifyManifest re-hashes runDir and reports the first difference from the
// recorded manifest: a missing file, a digest change or an extra file.
func VerifyManifest(runDir string) error {
	path := filepath.Join(runDir, ManifestFilename)
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read manifest %s: %w", path, err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("parse manifest %s: %w", path, err)
	}
	if manifest.Algorithm != manifestAlgorithm {
		return fmt.Errorf("verify manifest %s: unsupported algorithm %q", path, manifest.Algorithm)
	}

	current, err := hashRunDir(runDir)
	if err != nil {
		return err
	}
	present := make(map[string]ManifestEntry, len(current))
	for _, entry := range current {
		present[entry.Path] = entry
	}

	expected := make([]ManifestEntry, len(manifest.Files))
	copy(expected, manifest.Files)
	sort.Slice(expected, func(i, j int) bool { return expected[i].Path < expected[j].Path })

	for _, want := range expected {
		got, ok := present[want.Path]
		if !ok {
			return fmt.Errorf("verify manifest %s: missing file %s", path, want.Path)
		}
		if got.Size != want.Size || got.SHA256 != want.SHA256 {
			return fmt.Errorf("verify manifest %s: checksum mismatch for %s", path, want.Path)
		}
		delete(present, want.Path)
	}

	if len(present) > 0 {
		extras := make([]string, 0, len(present))
		for name := range present {
			extras = append(extras, name)
		}
		sort.Strings(extras)
		return fmt.Errorf("verify manifest %s: unexpected file %s", path, extras[0])
	}
	return nil
}

// hashRunDir returns sorted digests of every regular file below runDir. It
// follows no symlinks: WalkDir reports them as non-regular entries, so a link
// pointing outside the run directory can never pull foreign content into the
// manifest.
func hashRunDir(runDir string) ([]ManifestEntry, error) {
	entries := make([]ManifestEntry, 0)
	err := filepath.WalkDir(runDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(runDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == ManifestFilename {
			return nil
		}
		entry, err := hashFile(path, rel)
		if err != nil {
			return err
		}
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("hash run directory %s: %w", runDir, err)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}

func hashFile(path, rel string) (ManifestEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return ManifestEntry{}, fmt.Errorf("open %s: %w", rel, err)
	}
	defer file.Close()

	digest := sha256.New()
	size, err := io.Copy(digest, file)
	if err != nil {
		return ManifestEntry{}, fmt.Errorf("hash %s: %w", rel, err)
	}
	return ManifestEntry{
		Path:   rel,
		Size:   size,
		SHA256: hex.EncodeToString(digest.Sum(nil)),
	}, nil
}
