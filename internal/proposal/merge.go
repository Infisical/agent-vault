package proposal

import (
	"fmt"

	"github.com/Infisical/agent-vault/internal/broker"
)

// MergeServices applies proposed service changes to existing services.
// Set-action services upsert (add or replace); delete-action services remove.
// Returns the merged slice and a list of warnings for no-op operations.
func MergeServices(existing []broker.Service, proposed []Service) ([]broker.Service, []string) {
	// Index existing services by host for O(1) lookup.
	hostIndex := make(map[string]int, len(existing))
	for i, s := range existing {
		hostIndex[s.Host] = i
	}

	merged := make([]broker.Service, len(existing))
	copy(merged, existing)

	// Track which indices to remove (from delete actions).
	removeSet := make(map[int]bool)

	var warnings []string
	for _, p := range proposed {
		switch p.Action {
		case ActionDelete:
			idx, exists := hostIndex[p.Host]
			if !exists {
				warnings = append(warnings, fmt.Sprintf("skipped delete for %q: host not found", p.Host))
				continue
			}
			removeSet[idx] = true
			delete(hostIndex, p.Host)

		default: // ActionSet: upsert
			svc := toBrokerService(p)
			if idx, exists := hostIndex[p.Host]; exists {
				// Replace existing service in place.
				merged[idx] = svc
			} else {
				// Append new service.
				hostIndex[p.Host] = len(merged)
				merged = append(merged, svc)
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
	var desc *string
	if p.Description != "" {
		d := p.Description
		desc = &d
	}
	svc := broker.Service{
		Host:        p.Host,
		Description: desc,
	}
	if p.Auth != nil {
		svc.Auth = *p.Auth
	}
	return svc
}
