package cmd

import (
	"reflect"
	"testing"
)

func TestNodeCompatModeSet(t *testing.T) {
	cases := []struct {
		in      string
		want    NodeCompatMode
		wantErr bool
	}{
		{"auto", NodeCompatAuto, false},
		{"AUTO", NodeCompatAuto, false},
		{"on", NodeCompatOn, false},
		{"true", NodeCompatOn, false},
		{"off", NodeCompatOff, false},
		{"false", NodeCompatOff, false},
		{"", NodeCompatMode(""), true},
		{"yes", NodeCompatMode(""), true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			var m NodeCompatMode
			err := m.Set(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Set(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if !tc.wantErr && m != tc.want {
				t.Errorf("Set(%q) -> %q, want %q", tc.in, m, tc.want)
			}
		})
	}
}

func TestNodeCompatEnabled(t *testing.T) {
	cases := []struct {
		name string
		mode NodeCompatMode
		cmd  string
		want bool
	}{
		{"on/openclaw", NodeCompatOn, "openclaw", true},
		{"on/node", NodeCompatOn, "node", true},
		{"on/any-bin", NodeCompatOn, "/opt/weird/bin", true},
		{"off/openclaw", NodeCompatOff, "openclaw", false},
		{"off/node", NodeCompatOff, "node", false},
		{"auto/openclaw bare", NodeCompatAuto, "openclaw", true},
		{"auto/openclaw absolute", NodeCompatAuto, "/usr/local/bin/openclaw", true},
		{"auto/openclaw nested", NodeCompatAuto, "/root/.openclaw/bin/openclaw", true},
		{"auto/node", NodeCompatAuto, "node", false},
		{"auto/codex (TLS-bridge concern, not Node compat)", NodeCompatAuto, "codex", false},
		{"auto/claude", NodeCompatAuto, "claude", false},
		{"empty mode falls back to auto", NodeCompatMode(""), "openclaw", true},
		{"empty mode + non-openclaw is false", NodeCompatMode(""), "node", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nodeCompatEnabled(tc.mode, tc.cmd); got != tc.want {
				t.Errorf("nodeCompatEnabled(%q, %q) = %v, want %v", tc.mode, tc.cmd, got, tc.want)
			}
		})
	}
}

func TestAppendNodeOptionsRequire(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		path string
		want []string
	}{
		{
			name: "no NODE_OPTIONS in env",
			env:  []string{"FOO=bar", "PATH=/bin"},
			path: "/x/preload.js",
			want: []string{"FOO=bar", "PATH=/bin", "NODE_OPTIONS=--require=/x/preload.js"},
		},
		{
			name: "preserves existing NODE_OPTIONS",
			env:  []string{"NODE_OPTIONS=--enable-source-maps", "FOO=bar"},
			path: "/x/preload.js",
			want: []string{"NODE_OPTIONS=--enable-source-maps --require=/x/preload.js", "FOO=bar"},
		},
		{
			name: "preserves an existing operator --require",
			env:  []string{"NODE_OPTIONS=--require=/op/their.js"},
			path: "/x/preload.js",
			want: []string{"NODE_OPTIONS=--require=/op/their.js --require=/x/preload.js"},
		},
		{
			name: "idempotent: re-adding the same require is a no-op",
			env:  []string{"NODE_OPTIONS=--require=/x/preload.js"},
			path: "/x/preload.js",
			want: []string{"NODE_OPTIONS=--require=/x/preload.js"},
		},
		{
			name: "idempotent in the middle of a chain",
			env:  []string{"NODE_OPTIONS=--enable-source-maps --require=/x/preload.js --max-old-space-size=4096"},
			path: "/x/preload.js",
			want: []string{"NODE_OPTIONS=--enable-source-maps --require=/x/preload.js --max-old-space-size=4096"},
		},
		{
			name: "empty existing NODE_OPTIONS value still works",
			env:  []string{"NODE_OPTIONS="},
			path: "/x/preload.js",
			want: []string{"NODE_OPTIONS=--require=/x/preload.js"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Copy to avoid aliasing across cases.
			in := append([]string(nil), tc.env...)
			got := appendNodeOptionsRequire(in, tc.path)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("appendNodeOptionsRequire(%v, %q):\n got: %v\nwant: %v", tc.env, tc.path, got, tc.want)
			}
		})
	}
}
