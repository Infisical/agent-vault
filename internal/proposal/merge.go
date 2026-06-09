package proposal

import (
	"fmt"

	"github.com/Infisical/agent-vault/internal/broker"
)

// MergeServices upserts and deletes by Name. Callers must normalize
// every input (existing + proposed) to have a non-empty Name first;
// MergeServices panics otherwise because the Name-keyed index would
// silently collapse empty-name entries onto the "" key and overwrite
// unrelated services — a data-loss class bug not worth papering over.
// Returns the merged slice and warnings for no-op operations.
func MergeServices(existing []broker.Service, proposed []Service) ([]broker.Service, []string) {
	for i, s := range existing {
		if s.Name == "" {
			panic(fmt.Sprintf("proposal.MergeServices: existing[%d] has empty Name (host=%q)", i, s.Host))
		}
	}
	for i, p := range proposed {
		if p.Name == "" {
			panic(fmt.Sprintf("proposal.MergeServices: proposed[%d] has empty Name (host=%q, action=%q)", i, p.Host, p.Action))
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
				// Enable/disable-only: preserve Auth/Host/Path.
				merged[idx].Enabled = p.Enabled
			case exists:
				next := toBrokerService(p)
				// Empty Substitutions means "leave existing alone";
				// callers clear by delete+recreate.
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
		Port:    p.Port,
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
