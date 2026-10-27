package screenshot

import (
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Save writes img as PNG under dir using the conventional
// "{ip}_{port}_{timestamp}.png" name and returns the resulting path.
//
// The timestamp is formatted in local time, matching the run folder name, so
// every time shown inside one evidence folder uses the same clock. The JSON
// and report timestamps stay in UTC and are labelled as such.
func Save(img image.Image, dir, ip string, port int, ts time.Time) (string, error) {
	if img == nil {
		return "", fmt.Errorf("no image to save")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create screenshot directory: %w", err)
	}

	name := fmt.Sprintf("%s_%d_%s.png", sanitize(ip), port, ts.Local().Format("20060102-150405"))
	path := filepath.Join(dir, name)

	// Captures show the live desktop and are sensitive evidence.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", fmt.Errorf("create screenshot: %w", err)
	}
	// Encode first so a failure does not leave an empty file that looks
	// like a successful capture.
	if err := png.Encode(f, img); err != nil {
		f.Close()
		os.Remove(path)
		return "", fmt.Errorf("encode screenshot: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close screenshot: %w", err)
	}
	return path, nil
}

// sanitize replaces characters that are unsafe in file names (notably
// the colons of IPv6 literals) while keeping the address readable.
func sanitize(ip string) string {
	ip = strings.TrimSpace(ip)
	replacer := strings.NewReplacer(
		":", "_",
		"/", "_",
		"\\", "_",
		" ", "_",
		"..", "_",
	)
	return replacer.Replace(ip)
}
