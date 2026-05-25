package infisical

import (
	"strings"
	"testing"
)

// TestFlattenSecretsRejectsDuplicateKeyAcrossPaths locks in the safety guard
// that protects against silent credential corruption when an operator's
// Infisical layout has the same key under two paths and Recursive=true. The
// alternative is last-write-wins on a non-deterministic order, which would
// silently inject the wrong credential into proxied requests.
func TestFlattenSecretsRejectsDuplicateKeyAcrossPaths(t *testing.T) {
	cases := []struct {
		name    string
		in      []rawSecret
		wantErr bool
		wantOut []Secret
	}{
		{
			name: "unique keys pass through",
			in: []rawSecret{
				{Key: "STRIPE_KEY", Value: "sk_1", Path: "/stripe"},
				{Key: "OPENAI_KEY", Value: "sk_2", Path: "/openai"},
			},
			wantOut: []Secret{
				{Key: "STRIPE_KEY", Value: "sk_1"},
				{Key: "OPENAI_KEY", Value: "sk_2"},
			},
		},
		{
			name: "duplicate key across paths fails with both paths in the error",
			in: []rawSecret{
				{Key: "API_KEY", Value: "v1", Path: "/stripe"},
				{Key: "API_KEY", Value: "v2", Path: "/openai"},
			},
			wantErr: true,
		},
		{
			name:    "empty input is allowed",
			in:      nil,
			wantOut: []Secret{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := flattenSecrets(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				// The whole point of the guard is that the operator can find
				// and fix the conflict. Both paths must appear in the error.
				if !strings.Contains(err.Error(), "/stripe") || !strings.Contains(err.Error(), "/openai") {
					t.Fatalf("error must name both conflicting paths; got %q", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(out) != len(tc.wantOut) {
				t.Fatalf("len: want %d, got %d", len(tc.wantOut), len(out))
			}
			for i := range out {
				if out[i] != tc.wantOut[i] {
					t.Fatalf("entry %d: want %+v, got %+v", i, tc.wantOut[i], out[i])
				}
			}
		})
	}
}
