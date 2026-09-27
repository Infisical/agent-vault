package proposal

import (
	"encoding/json"
	"fmt"

	"github.com/Infisical/agent-vault/internal/broker"
)

// ExplicitFilterIndex reports the first proposed service whose JSON object
// contains a filter key. Proposals cannot author, replace, or clear a filter.
func ExplicitFilterIndex(services json.RawMessage) (int, bool) {
	if len(services) == 0 {
		return 0, false
	}
	var arr []map[string]json.RawMessage
	if err := json.Unmarshal(services, &arr); err != nil {
		return 0, false
	}
	for i, obj := range arr {
		if _, ok := obj["filter"]; ok {
			return i, true
		}
	}
	return 0, false
}

// CheckFilterPolicy rejects a proposal that deletes a filtered service or
// whose effective unfiltered matcher can win or tie an existing filtered
// service. Create maps the error to 400. Apply maps it to 409.
func CheckFilterPolicy(existing []broker.Service, proposed []Service) error {
	byName := make(map[string]broker.Service, len(existing))
	for _, svc := range existing {
		byName[svc.Name] = svc
	}
	for _, p := range proposed {
		if p.Action != ActionDelete {
			continue
		}
		cur, ok := byName[p.Name]
		if ok && cur.Filter != nil {
			return fmt.Errorf("cannot delete filtered service %q; disable it or remove the filter in admin config", p.Name)
		}
	}
	merged, _ := MergeServices(existing, proposed)
	mergedByName := make(map[string]broker.Service, len(merged))
	for _, svc := range merged {
		mergedByName[svc.Name] = svc
	}
	for _, p := range proposed {
		if p.Action != ActionSet || p.Name == "" {
			continue
		}
		eff, ok := mergedByName[p.Name]
		if !ok {
			continue
		}
		if cur, had := byName[p.Name]; had && cur.Filter != nil && filterMatcherChanged(cur, eff) {
			return fmt.Errorf("cannot change host, path, or port of filtered service %q", p.Name)
		}
		if eff.Filter != nil {
			continue
		}
		for _, other := range merged {
			if other.Name == eff.Name || other.Filter == nil {
				continue
			}
			if broker.ShadowsFiltered(eff, other) {
				return fmt.Errorf("service %q would win or tie filtered service %q", eff.Name, other.Name)
			}
		}
	}
	return nil
}

func filterMatcherChanged(cur, eff broker.Service) bool {
	if cur.Host != eff.Host || cur.Path != eff.Path {
		return true
	}
	if (cur.Port == nil) != (eff.Port == nil) {
		return true
	}
	if cur.Port != nil && *cur.Port != *eff.Port {
		return true
	}
	return false
}
