package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Document is the on-disk JSON shape: metadata plus every probe result.
type Document struct {
	GeneratedAt time.Time `json:"generated_at"`
	Tool        string    `json:"tool"`
	Summary     Summary   `json:"summary"`
	Results     []Result  `json:"results"`
}

// WriteJSON saves the full result set to path.
func WriteJSON(path string, results []Result) error {
	doc := Document{
		GeneratedAt: time.Now().UTC(),
		Tool:        "vncshot",
		Summary:     Summarize(results),
		Results:     results,
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	data = append(data, '\n')

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write json report: %w", err)
	}
	return nil
}
