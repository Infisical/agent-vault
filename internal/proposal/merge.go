package proposal

import (
	"fmt"

	"github.com/Infisical/agent-vault/internal/broker"
)

// MergeServices applies proposed service changes to existing services,
// indexed by canonical service Name. Set-action services upsert (add or
// replace by Name); delete-action services remove by Name. Callers must
// have already populated Name on every existing and proposed service —
// server handlers run broker.NormalizeServices on existing and auto-slug
// proposals via broker.Slugify before reaching MergeServices. Returns
// the merged slice and a list of warnings for no-op operations.
//
// Panics if any input has an empty Name. The Name-keyed index would
// otherwise collapse every empty-name entry onto the "" key and the
// last writer would silently overwrite the rest — a class of data-loss
// bug worth crashing on rather than papering over, since the contract
// is a programming-error invariant.
func MergeServices(existing []broker.Service, proposed []Service) ([]broker.Service, []string) {
	for i, s := range existing {
		if s.Name == "" {
			panic(fmt.Sprintf("proposal.MergeServices: existing[%d] has empty Name (host=%q) — caller must normalize first", i, s.Host))
		}
	}
	for i, p := range proposed {
		if p.Name == "" {
			panic(fmt.Sprintf("proposal.MergeServices: proposed[%d] has empty Name (host=%q, action=%q) — caller must normalize first", i, p.Host, p.Action))
		}
	}
	nameIndex := make(map[string]int, len(existing))
	for i, s := range existing {
		nameIndex[s.Name] = i
	}

	merged := make([]broker.Service, len(existing))
	copy(merged, existing)

	// Track which indices to remove (from delete actions).
	removeSet := make(map[int]bool)

	var warnings []string
	for _, p := range proposed {
		switch p.Action {
		case ActionDelete:
			idx, exists := nameIndex[p.Name]
			if !exists {
				warnings = append(warnings, fmt.Sprintf("skipped delete for %q: service not found", p.Name))
				continue
			}
			removeSet[idx] = true
			delete(nameIndex, p.Name)

		default: // ActionSet: upsert
			idx, exists := nameIndex[p.Name]
			switch {
			case exists && p.Auth == nil && p.Enabled != nil:
				// Enable/disable-only change on an existing service:
				// preserve Auth, Host, and Path, overlay just the flag.
				merged[idx].Enabled = p.Enabled
			case exists:
				next := toBrokerService(p)
				// Empty Substitutions means "leave existing alone"; clear
				// by delete+recreate. The aliased slice is safe — the
				// caller marshals the merged config to JSON and does not
				// mutate it.
				if len(p.Substitutions) == 0 {
					next.Substitutions = merged[idx].Substitutions
				}
				merged[idx] = next
			default:
				nameIndex[p.Name] = len(merged)
				merged = append(merged, toBrokerService(p))
			}
		}
	}

	// Remove deleted services (iterate in reverse-stable order).
	if len(removeSet) > 0 {
		result := make([]broker.Service, 0, len(merged)-len(removeSet))
		for i, s := range merged {
			if !removeSet[i] {
				result = append(result, s)
			}
		}
		merged = result
	}

	return merged, warnings
}

func toBrokerService(p Service) broker.Service {
	svc := broker.Service{
		Name:    p.Name,
		Host:    p.Host,
		Path:    p.Path,
		Enabled: p.Enabled,
	}
	if p.Auth != nil {
		svc.Auth = *p.Auth
	}
	if len(p.Substitutions) > 0 {
		svc.Substitutions = make([]broker.Substitution, len(p.Substitutions))
		copy(svc.Substitutions, p.Substitutions)
	}
	return svc
}
