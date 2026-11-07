package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
)

func TestServiceFileSerializationPreservesRouteFieldPresence(t *testing.T) {
	tests := []struct {
		name   string
		yaml   string
		fields map[string]string
		port   int
	}{
		{
			name:   "omitted preserves server route",
			yaml:   "services:\n  - name: legacy\n    host: example.com/api/*\n    auth:\n      type: passthrough\n",
			fields: map[string]string{},
		},
		{
			name:   "explicit false selects direct",
			yaml:   "services:\n  - name: named\n    host: example.com:8443/api/*\n    auth:\n      type: passthrough\n    use_upstream_proxy: false\n",
			fields: map[string]string{"use_upstream_proxy": "false"},
			port:   8443,
		},
		{
			name:   "explicit empty profile selects direct",
			yaml:   "services:\n  - name: default\n    host: example.com/api/*\n    auth:\n      type: passthrough\n    upstream_proxy: \"\"\n",
			fields: map[string]string{"upstream_proxy": `""`},
		},
		{
			name:   "bypass remains explicit",
			yaml:   "services:\n  - name: direct\n    host: example.com/api/*\n    auth:\n      type: passthrough\n    bypass_upstream_proxy: true\n",
			fields: map[string]string{"bypass_upstream_proxy": "true"},
		},
		{
			name:   "yaml yes coerces to typed boolean",
			yaml:   "services:\n  - name: direct\n    host: example.com/api/*\n    auth:\n      type: passthrough\n    bypass_upstream_proxy: yes\n",
			fields: map[string]string{"bypass_upstream_proxy": "true"},
		},
		{
			name:   "yaml no preserves explicit false",
			yaml:   "services:\n  - name: direct\n    host: example.com/api/*\n    auth:\n      type: passthrough\n    use_upstream_proxy: no\n",
			fields: map[string]string{"use_upstream_proxy": "false"},
		},
		{
			name:   "numeric profile name stays a string",
			yaml:   "services:\n  - name: named\n    host: example.com/api/*\n    auth:\n      type: passthrough\n    upstream_proxy: 123\n",
			fields: map[string]string{"upstream_proxy": `"123"`},
		},
		{
			name:   "aliased service preserves explicit false",
			yaml:   "template: &service\n  name: named\n  host: example.com/api/*\n  auth:\n    type: passthrough\n  use_upstream_proxy: false\nservices:\n  - *service\n",
			fields: map[string]string{"use_upstream_proxy": "false"},
		},
		{
			name:   "merged route preserves explicit empty profile",
			yaml:   "route: &route\n  upstream_proxy: \"\"\nservices:\n  - <<: *route\n    name: named\n    host: example.com/api/*\n    auth:\n      type: passthrough\n",
			fields: map[string]string{"upstream_proxy": `""`},
		},
		{
			name:   "explicit null remains explicit",
			yaml:   "services:\n  - name: named\n    host: example.com/api/*\n    auth:\n      type: passthrough\n    upstream_proxy: null\n",
			fields: map[string]string{"upstream_proxy": "null"},
		},
		{
			name:   "contradictory controls are preserved for server rejection",
			yaml:   "services:\n  - name: invalid\n    host: example.com/api/*\n    auth:\n      type: passthrough\n    use_upstream_proxy: true\n    upstream_proxy: corp-egress\n",
			fields: map[string]string{"use_upstream_proxy": "true", "upstream_proxy": `"corp-egress"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "services.yaml")
			if err := os.WriteFile(path, []byte(tt.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			entries, err := loadServicesFromFile(path, "default")
			if err != nil {
				t.Fatal(err)
			}
			got, err := marshalServiceFileEntries(entries)
			if err != nil {
				t.Fatal(err)
			}
			var services []map[string]json.RawMessage
			if err := json.Unmarshal(got, &services); err != nil {
				t.Fatal(err)
			}
			if len(services) != 1 {
				t.Fatalf("got %d serialized services, want 1", len(services))
			}
			var accepted []broker.Service
			if err := json.Unmarshal(got, &accepted); err != nil {
				t.Fatalf("server cannot decode serialized services: %v", err)
			}
			if accepted[0].UpstreamProxy != entries[0].Service.UpstreamProxy ||
				accepted[0].UseUpstreamProxy != entries[0].Service.UseUpstreamProxy ||
				accepted[0].BypassUpstreamProxy != entries[0].Service.BypassUpstreamProxy {
				t.Errorf("route changed on server decode: got %+v, parsed %+v", accepted[0], entries[0].Service)
			}
			for field, want := range tt.fields {
				if got := string(services[0][field]); got != want {
					t.Errorf("%s = %q, want %q", field, got, want)
				}
			}
			for field := range map[string]bool{
				"use_upstream_proxy":    true,
				"upstream_proxy":        true,
				"bypass_upstream_proxy": true,
			} {
				if _, wantPresent := tt.fields[field]; !wantPresent {
					if _, present := services[0][field]; present {
						t.Errorf("omitted route field %q was serialized", field)
					}
				}
			}
			gotPort := 0
			if entries[0].Service.Port != nil {
				gotPort = *entries[0].Service.Port
			}
			if entries[0].Service.Host != "example.com" || entries[0].Service.Path != "/api/*" || gotPort != tt.port {
				t.Errorf("inline host was not preserved/split correctly: %+v", entries[0].Service)
			}
		})
	}
}
