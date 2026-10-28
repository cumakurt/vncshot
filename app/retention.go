package app

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// RunInfo describes one timestamped run directory below the report root.
type RunInfo struct {
	Name    string
	Started time.Time
	// Size is the sum of the regular files in the run directory.
	Size int64
	// Files is the number of regular files in the run directory.
	Files int
}

// deniedReportRoots are filesystem locations where deleting run directories
// can never be justified. The list is intentionally short and matched
// exactly against the resolved report root.
var deniedReportRoots = []string{
	"/",
	"/root",
	"/home",
	"/tmp",
	"/usr",
	"/var",
}

// ListRuns returns the run directories directly below root, newest first.
// Only names that parse with RunTimestampLayout are considered. Symlinks,
// plain files and unrelated directories are ignored, and sizes are computed
// from regular files without following symlinks.
func ListRuns(root string) ([]RunInfo, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []RunInfo{}, nil
		}
		return nil, fmt.Errorf("list report root %s: %w", root, err)
	}

	runs := make([]RunInfo, 0, len(entries))
	for _, entry := range entries {
		// Never follow a link: a symlinked "run" could point outside the
		// report root and a later prune would delete foreign data.
		if entry.Type()&fs.ModeSymlink != 0 {
			continue
		}
		if !entry.IsDir() {
			continue
		}
		started, err := time.ParseInLocation(RunTimestampLayout, entry.Name(), time.Local)
		if err != nil {
			continue
		}

		size, files, err := runUsage(filepath.Join(root, entry.Name()))
		if err != nil {
			return nil, err
		}
		runs = append(runs, RunInfo{
			Name:    entry.Name(),
			Started: started,
			Size:    size,
			Files:   files,
		})
	}

	sort.Slice(runs, func(i, j int) bool {
		if runs[i].Started.Equal(runs[j].Started) {
			return runs[i].Name > runs[j].Name
		}
		return runs[i].Started.After(runs[j].Started)
	})
	return runs, nil
}

// runUsage totals the regular files below dir. filepath.WalkDir does not
// follow symlinks, so linked content is neither measured nor counted.
func runUsage(dir string) (int64, int, error) {
	var size int64
	files := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		size += info.Size()
		files++
		return nil
	})
	if err != nil {
		return 0, 0, fmt.Errorf("measure run directory %s: %w", dir, err)
	}
	return size, files, nil
}

// PruneRuns keeps the newest keep runs below root and removes the remaining
// run directories. With dryRun it reports what it would remove and deletes
// nothing. keep must be positive so a zero value can never wipe history.
//
// protect names run directories that must survive pruning even when they are
// old enough to fall in the removed set. Callers pass the resume source so a
// continued run never loses the evidence the resumed report still points at;
// entries may be given as bare run directory names or full paths.
func PruneRuns(root string, keep int, dryRun bool, protect ...string) (removed []RunInfo, err error) {
	if keep < 0 {
		return nil, fmt.Errorf("keep must not be negative")
	}
	if keep == 0 {
		return nil, fmt.Errorf("refusing to delete every run; pass a positive -keep")
	}

	resolved, err := resolveRetentionRoot(root)
	if err != nil {
		return nil, err
	}

	runs, err := ListRuns(resolved)
	if err != nil {
		return nil, err
	}
	if len(runs) <= keep {
		return nil, nil
	}

	// ListRuns only returns directories whose names parse as run folders,
	// so unrelated entries and plain files in the report root are never
	// candidates for deletion.
	stale := runs[keep:]
	removed = make([]RunInfo, 0, len(stale))
	for _, run := range stale {
		if protectedNames(protect)[run.Name] {
			continue
		}
		removed = append(removed, run)
		if dryRun {
			continue
		}
		path := filepath.Join(resolved, run.Name)
		if err := os.RemoveAll(path); err != nil {
			return removed, fmt.Errorf("remove run directory %s: %w", path, err)
		}
	}
	return removed, nil
}

// protectedNames resolves protect entries to run directory names. Full paths
// are reduced to their base name only when it parses as a run folder name,
// which is the identity ListRuns reports; anything else cannot match a run
// directory and is ignored.
func protectedNames(protect []string) map[string]bool {
	names := make(map[string]bool, len(protect))
	for _, entry := range protect {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		names[filepath.Base(filepath.Clean(entry))] = true
	}
	return names
}

// resolveRetentionRoot validates the report root before anything is removed.
// It rejects symlinked roots rather than silently following them, and refuses
// filesystem locations where the directory name alone is not enough evidence
// that the contents are run folders.
func resolveRetentionRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", fmt.Errorf("refusing to prune an empty report root")
	}

	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve report root %s: %w", root, err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("report root %s does not exist", abs)
		}
		return "", fmt.Errorf("inspect report root %s: %w", abs, err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return "", fmt.Errorf("refusing to prune symlinked report root %s", abs)
	}

	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve report root %s: %w", abs, err)
	}
	resolved = filepath.Clean(resolved)

	resolvedInfo, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("inspect report root %s: %w", resolved, err)
	}
	if !resolvedInfo.IsDir() {
		return "", fmt.Errorf("report root %s is not a directory", resolved)
	}

	for _, denied := range deniedReportRoots {
		if resolved == denied {
			return "", fmt.Errorf("refusing to prune report root %s", resolved)
		}
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if resolved == filepath.Clean(home) {
			return "", fmt.Errorf("refusing to prune the home directory %s", resolved)
		}
	}
	return resolved, nil
}

// RetainRuns applies the session's configured retention policy to the report
// root that holds this session's run directory.
func (s *Session) RetainRuns() (removed []RunInfo, err error) {
	protect := []string(nil)
	if s.config.ResumeDir != "" {
		// The resume source keeps the screenshots and evidence the resumed
		// report still references, so it must survive retention.
		protect = append(protect, s.config.ResumeDir)
	}
	return PruneRuns(s.ReportRoot(), s.config.KeepRuns, s.config.PruneDryRun, protect...)
}
