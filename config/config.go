// Package config applies flag defaults from a config file and from
// VNCSHOT_* environment variables.
//
// Precedence, highest first:
//
//	command-line flag > environment variable > config file > built-in default
//
// A value is only applied when the operator did not set the flag on the
// command line, so an explicit flag always wins.
package config

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// EnvPrefix is prepended to the upper-case flag name to build the
// environment variable that overrides it (-out-dir -> VNCSHOT_OUT_DIR).
const EnvPrefix = "VNCSHOT_"

// Load reads a JSON or simple YAML config file into a flat key/value map.
// An empty path yields an empty map, which lets callers treat "no config"
// and "empty config" the same way.
func Load(path string) (map[string]any, error) {
	values := make(map[string]any)
	if strings.TrimSpace(path) == "" {
		return values, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		if err := json.Unmarshal(data, &values); err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
	default:
		parsed, err := parseSimpleYAML(data)
		if err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
		values = parsed
	}
	return values, nil
}

// parseSimpleYAML parses the flat "key: value" subset the tool supports.
// It deliberately rejects anything else (nesting, lists, block scalars) so a
// mistyped config fails loudly instead of being silently ignored.
func parseSimpleYAML(data []byte) (map[string]any, error) {
	values := make(map[string]any)

	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "---") {
			continue
		}

		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("line %d: expected \"key: value\", got %q", i+1, line)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("line %d: empty key", i+1)
		}
		if strings.ContainsAny(key, " \t\"'") {
			return nil, fmt.Errorf("line %d: invalid key %q", i+1, key)
		}

		parsed, err := parseScalar(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("line %d (%s): %w", i+1, key, err)
		}
		if _, dup := values[key]; dup {
			return nil, fmt.Errorf("line %d: duplicate key %q", i+1, key)
		}
		values[key] = parsed
	}
	return values, nil
}

// parseScalar converts a YAML scalar to a Go value. Booleans, integers and
// floats are typed; everything else stays a string so durations such as
// "1s" reach flag.DurationVar intact.
func parseScalar(raw string) (any, error) {
	if raw == "" {
		return "", nil
	}

	// Quoted scalars are taken literally, with the quote removed.
	if len(raw) >= 2 {
		if (raw[0] == '"' && raw[len(raw)-1] == '"') || (raw[0] == '\'' && raw[len(raw)-1] == '\'') {
			inner := raw[1 : len(raw)-1]
			if strings.ContainsAny(inner, "\n\r") {
				return nil, errors.New("multi-line values are not supported")
			}
			return inner, nil
		}
	}

	// A trailing comment is only stripped for unquoted scalars.
	if idx := strings.Index(raw, " #"); idx >= 0 {
		raw = strings.TrimSpace(raw[:idx])
		if raw == "" {
			return "", nil
		}
	}

	switch strings.ToLower(raw) {
	case "true", "yes", "on":
		return true, nil
	case "false", "no", "off":
		return false, nil
	case "null", "~":
		return nil, nil
	}

	if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return n, nil
	}
	if f, err := strconv.ParseFloat(raw, 64); err == nil {
		return f, nil
	}
	return raw, nil
}

// Apply sets flag values from the environment and then from the config map,
// skipping every flag the operator already set on the command line.
func Apply(fs *flag.FlagSet, values map[string]any) error {
	set := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	// Environment before the file so the file never overrides the
	// environment.
	var envErr error
	fs.VisitAll(func(f *flag.Flag) {
		if set[f.Name] || envErr != nil {
			return
		}
		envKey := EnvPrefix + envName(f.Name)
		raw, ok := os.LookupEnv(envKey)
		if !ok || strings.TrimSpace(raw) == "" {
			return
		}
		if err := fs.Set(f.Name, strings.TrimSpace(raw)); err != nil {
			envErr = fmt.Errorf("environment %s: %w", envKey, err)
			return
		}
		set[f.Name] = true
	})
	if envErr != nil {
		return envErr
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	// Deterministic order keeps error messages stable across runs.
	sort.Strings(keys)

	for _, key := range keys {
		if set[key] {
			continue
		}
		if fs.Lookup(key) == nil {
			return fmt.Errorf("config: unknown key %q", key)
		}
		raw, err := formatValue(values[key])
		if err != nil {
			return fmt.Errorf("config: key %q: %w", key, err)
		}
		if err := fs.Set(key, raw); err != nil {
			return fmt.Errorf("config: key %q: %w", key, err)
		}
	}
	return nil
}

// envName converts a flag name to its environment suffix.
func envName(flagName string) string {
	return strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// formatValue renders a config value in the textual form flag.Set expects.
func formatValue(v any) (string, error) {
	switch value := v.(type) {
	case nil:
		return "", nil
	case string:
		return value, nil
	case bool:
		return strconv.FormatBool(value), nil
	case int:
		return strconv.Itoa(value), nil
	case int64:
		return strconv.FormatInt(value, 10), nil
	case float64:
		// JSON numbers arrive as float64; keep integers integral so
		// "workers: 200" does not become "200.000000".
		if value == float64(int64(value)) {
			return strconv.FormatInt(int64(value), 10), nil
		}
		return strconv.FormatFloat(value, 'f', -1, 64), nil
	default:
		return "", fmt.Errorf("unsupported value type %T", v)
	}
}
