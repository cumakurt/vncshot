package app

import (
	"fmt"

	"vncshot/scanner"
)

// Plan summarises the scope of a scan without performing it. It lets an
// operator sanity-check a large CIDR or port list before any packet leaves
// the host.
type Plan struct {
	// Targets is the number of host:port pairs that would be probed.
	Targets int
	// Hosts is the number of unique hosts after expansion and deduplication.
	Hosts int
	// Ports is the number of distinct ports.
	Ports int
	// Credentials is the number of password candidates per RFB endpoint.
	Credentials int
	// Excluded is the number of host:port pairs the exclusion list dropped.
	// They are never contacted; the dry run shows the boundary explicitly.
	Excluded int
	// First and Last are the first and last target in scan order, useful to
	// spot an off-by-one in a range.
	First string
	Last  string
}

// DescribeScope expands the configured scope and returns its size. It
// creates no directories and sends no traffic.
func DescribeScope(cfg Config, ports []int) (Plan, error) {
	targets, err := scanner.ParseTargets(cfg.Target, cfg.File, ports)
	if err != nil {
		return Plan{}, err
	}
	// Exclusions shrink the scope the same way they do for a real scan, so
	// a dry run shows the boundary the operator is about to enforce.
	var excluded int
	if cfg.ExcludeFile != "" {
		exclusions, err := LoadExclusions(cfg.ExcludeFile)
		if err != nil {
			return Plan{}, fmt.Errorf("exclusion list requested: %w", err)
		}
		kept, dropped := exclusions.Filter(targets)
		targets = kept
		excluded = len(dropped)
		if len(targets) == 0 {
			return Plan{}, fmt.Errorf("every target is excluded by %s; nothing to scan", cfg.ExcludeFile)
		}
	}
	creds, err := Credentials(cfg)
	if err != nil {
		return Plan{}, err
	}

	plan := Plan{
		Targets:     len(targets),
		Ports:       len(ports),
		Credentials: len(creds),
		Excluded:    excluded,
	}

	hosts := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		hosts[t.IP] = struct{}{}
	}
	plan.Hosts = len(hosts)

	if len(targets) > 0 {
		// Report the extremes in scan order so a mistyped range is obvious.
		plan.First = targets[0].Addr()
		plan.Last = targets[len(targets)-1].Addr()
	}
	return plan, nil
}
