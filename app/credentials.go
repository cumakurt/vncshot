package app

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"vncshot/vnc"
)

// maxWordListEntries bounds a word list so one scan cannot turn into an
// unbounded guessing campaign against a live desktop.
const maxWordListEntries = 500

// Credentials assembles the password candidates for a scan: the built-in
// weak-password list plus, optionally, an operator-supplied word list.
// Duplicates are removed while preserving order.
func Credentials(cfg Config) ([]vnc.Credential, error) {
	if cfg.NoPasswordCheck {
		return nil, nil
	}

	var creds []vnc.Credential
	if !cfg.NoDefaultPasswords {
		creds = append(creds, vnc.DefaultCredentials()...)
	}

	if path := strings.TrimSpace(cfg.WordList); path != "" {
		fromFile, err := readWordList(path)
		if err != nil {
			return nil, err
		}
		creds = append(creds, fromFile...)
	}

	seen := make(map[string]struct{}, len(creds))
	out := creds[:0]
	for _, c := range creds {
		key := c.Source + "\x00" + c.Password
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, c)
	}
	return out, nil
}

// readWordList loads one password per line. Blank lines and lines starting
// with '#' are ignored; surrounding whitespace is preserved only when it is
// part of the line content after trimming the newline.
func readWordList(path string) ([]vnc.Credential, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open word list %s: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat word list %s: %w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("word list %s is a directory", path)
	}

	var out []vnc.Credential
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if len(out) >= maxWordListEntries {
			return nil, fmt.Errorf("word list %s exceeds the %d-entry limit", path, maxWordListEntries)
		}
		out = append(out, vnc.Credential{Password: trimmed, Source: vnc.SourceWordList})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read word list %s: %w", path, err)
	}
	return out, nil
}
