package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func writeRunFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create directory for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func sha256Hex(content string) string {
	digest := sha256.Sum256([]byte(content))
	return hex.EncodeToString(digest[:])
}

func readManifest(t *testing.T, runDir string) (Manifest, os.FileInfo) {
	t.Helper()
	path := filepath.Join(runDir, ManifestFilename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("manifest is not valid JSON: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat manifest: %v", err)
	}
	return manifest, info
}

func TestWriteManifestListsEveryArtifact(t *testing.T) {
	runDir := t.TempDir()
	files := map[string]string{
		"vncshot_report.json": `{"results":[]}`,
		"vncshot_report.csv":  "ip,port\n10.0.0.1,5900\n",
		"sub/notes.txt":       "attachment note",
	}
	for name, content := range files {
		writeRunFile(t, filepath.Join(runDir, name), content)
	}

	path, err := WriteManifest(runDir)
	if err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	if path != filepath.Join(runDir, ManifestFilename) {
		t.Errorf("manifest path = %q, want %q", path, filepath.Join(runDir, ManifestFilename))
	}

	manifest, info := readManifest(t, runDir)
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("manifest mode = %o, want 600", mode)
	}
	if manifest.Algorithm != "sha256" {
		t.Errorf("algorithm = %q, want sha256", manifest.Algorithm)
	}
	if manifest.Root != filepath.Base(runDir) {
		t.Errorf("root = %q, want %q", manifest.Root, filepath.Base(runDir))
	}
	if !strings.HasSuffix(manifest.GeneratedAt, "Z") {
		t.Errorf("generated_at = %q, want a UTC RFC3339 timestamp", manifest.GeneratedAt)
	}

	wantPaths := []string{"sub/notes.txt", "vncshot_report.csv", "vncshot_report.json"}
	sort.Strings(wantPaths)
	gotPaths := make([]string, len(manifest.Files))
	for i, entry := range manifest.Files {
		gotPaths[i] = entry.Path
		if entry.Path == ManifestFilename {
			t.Error("manifest lists itself")
		}
		want := files[entry.Path]
		if entry.Size != int64(len(want)) {
			t.Errorf("%s size = %d, want %d", entry.Path, entry.Size, len(want))
		}
		if entry.SHA256 != sha256Hex(want) {
			t.Errorf("%s digest = %q, want %q", entry.Path, entry.SHA256, sha256Hex(want))
		}
	}
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Errorf("entries = %v, want sorted %v", gotPaths, wantPaths)
	}
}

func TestWriteManifestIsIdempotent(t *testing.T) {
	runDir := t.TempDir()
	writeRunFile(t, filepath.Join(runDir, "vncshot_report.json"), `{"results":[]}`)
	writeRunFile(t, filepath.Join(runDir, "vncshot_report.csv"), "ip,port\n")

	if _, err := WriteManifest(runDir); err != nil {
		t.Fatalf("first WriteManifest: %v", err)
	}
	first, _ := readManifest(t, runDir)
	if _, err := WriteManifest(runDir); err != nil {
		t.Fatalf("second WriteManifest: %v", err)
	}
	second, _ := readManifest(t, runDir)

	if !reflect.DeepEqual(first.Files, second.Files) {
		t.Errorf("file list changed between calls:\nfirst:  %+v\nsecond: %+v", first.Files, second.Files)
	}
}

func TestVerifyManifestPassesForUntouchedRun(t *testing.T) {
	runDir := t.TempDir()
	writeRunFile(t, filepath.Join(runDir, "vncshot_report.json"), `{"results":[]}`)
	writeRunFile(t, filepath.Join(runDir, "screenshots/host.png"), "png bytes")
	if _, err := WriteManifest(runDir); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	if err := VerifyManifest(runDir); err != nil {
		t.Fatalf("VerifyManifest: %v", err)
	}
}

func TestVerifyManifestDetectsTampering(t *testing.T) {
	runDir := t.TempDir()
	writeRunFile(t, filepath.Join(runDir, "vncshot_report.json"), `{"results":[]}`)
	if _, err := WriteManifest(runDir); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	writeRunFile(t, filepath.Join(runDir, "vncshot_report.json"), `{"results":[{"ip":"10.0.0.1"}]}`)
	err := VerifyManifest(runDir)
	if err == nil {
		t.Fatal("VerifyManifest accepted a modified file")
	}
	if !strings.Contains(err.Error(), "vncshot_report.json") {
		t.Errorf("error %q does not name the modified file", err)
	}
}

func TestVerifyManifestDetectsMissingFile(t *testing.T) {
	runDir := t.TempDir()
	writeRunFile(t, filepath.Join(runDir, "vncshot_report.json"), `{"results":[]}`)
	writeRunFile(t, filepath.Join(runDir, "vncshot_report.csv"), "ip,port\n")
	if _, err := WriteManifest(runDir); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	if err := os.Remove(filepath.Join(runDir, "vncshot_report.csv")); err != nil {
		t.Fatalf("remove artifact: %v", err)
	}
	err := VerifyManifest(runDir)
	if err == nil {
		t.Fatal("VerifyManifest accepted a missing file")
	}
	if !strings.Contains(err.Error(), "vncshot_report.csv") {
		t.Errorf("error %q does not name the missing file", err)
	}
}

func TestVerifyManifestDetectsUnexpectedFile(t *testing.T) {
	runDir := t.TempDir()
	writeRunFile(t, filepath.Join(runDir, "vncshot_report.json"), `{"results":[]}`)
	if _, err := WriteManifest(runDir); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	writeRunFile(t, filepath.Join(runDir, "injected.txt"), "unexpected")
	err := VerifyManifest(runDir)
	if err == nil {
		t.Fatal("VerifyManifest accepted an unexpected file")
	}
	if !strings.Contains(err.Error(), "injected.txt") {
		t.Errorf("error %q does not name the unexpected file", err)
	}
}

func TestVerifyManifestRejectsMissingManifest(t *testing.T) {
	if err := VerifyManifest(t.TempDir()); err == nil {
		t.Fatal("VerifyManifest accepted a directory without a manifest")
	}
}

// A symlink must not pull content from outside the run directory into the
// checksum manifest.
func TestWriteManifestSkipsSymlinks(t *testing.T) {
	outside := t.TempDir()
	outsidePath := filepath.Join(outside, "secret.txt")
	writeRunFile(t, outsidePath, "outside content")

	runDir := t.TempDir()
	writeRunFile(t, filepath.Join(runDir, "vncshot_report.json"), `{"results":[]}`)
	if err := os.Symlink(outsidePath, filepath.Join(runDir, "link.txt")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	if _, err := WriteManifest(runDir); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	manifest, _ := readManifest(t, runDir)
	for _, entry := range manifest.Files {
		if entry.Path == "link.txt" {
			t.Error("manifest followed a symlink")
		}
	}
	if err := VerifyManifest(runDir); err != nil {
		t.Errorf("VerifyManifest: %v", err)
	}
}
