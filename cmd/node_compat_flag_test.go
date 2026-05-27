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
		args []string
		want bool
	}{
		// ---- explicit modes ----
		{"on/openclaw", NodeCompatOn, []string{"openclaw"}, true},
		{"on/node", NodeCompatOn, []string{"node", "foo.js"}, true},
		{"on/any-bin", NodeCompatOn, []string{"/opt/weird/bin"}, true},
		{"off/openclaw", NodeCompatOff, []string{"openclaw"}, false},
		{"off/node-wrapping-openclaw", NodeCompatOff, []string{"/usr/bin/node", "/usr/lib/node_modules/openclaw/dist/index.js"}, false},

		// ---- auto: bare openclaw binary ----
		{"auto/openclaw bare", NodeCompatAuto, []string{"openclaw"}, true},
		{"auto/openclaw absolute", NodeCompatAuto, []string{"/usr/local/bin/openclaw"}, true},
		{"auto/openclaw nested", NodeCompatAuto, []string{"/root/.openclaw/bin/openclaw"}, true},
		{"auto/openclaw with args", NodeCompatAuto, []string{"openclaw", "gateway", "start"}, true},

		// ---- auto: node-wrapped openclaw (the systemd-unit shape) ----
		{
			"auto/node /usr/lib/node_modules/openclaw/dist/index.js (linux global npm)",
			NodeCompatAuto,
			[]string{"/usr/bin/node", "/usr/lib/node_modules/openclaw/dist/index.js", "gateway", "--port", "18789"},
			true,
		},
		{
			"auto/node /opt/homebrew/lib/node_modules/openclaw/dist/index.js (macOS Homebrew)",
			NodeCompatAuto,
			[]string{"/usr/local/bin/node", "/opt/homebrew/lib/node_modules/openclaw/dist/index.js"},
			true,
		},
		{
			"auto/node /root/.openclaw/npm/node_modules/openclaw/dist/index.js (per-user npm)",
			NodeCompatAuto,
			[]string{"node", "/root/.openclaw/npm/node_modules/openclaw/dist/index.js"},
			true,
		},
		{
			"auto/nodejs /path/to/openclaw/cli.js (Debian-style nodejs binary)",
			NodeCompatAuto,
			[]string{"nodejs", "/some/path/openclaw/cli.js"},
			true,
		},
		{
			"auto/node /path/to/@openclaw/cli/dist/index.js (scoped package)",
			NodeCompatAuto,
			[]string{"node", "/usr/lib/node_modules/@openclaw/cli/dist/index.js"},
			true,
		},
		{
			"auto/node with flags before script",
			NodeCompatAuto,
			[]string{"node", "--enable-source-maps", "--max-old-space-size=4096", "/usr/lib/node_modules/openclaw/dist/index.js"},
			true,
		},

		// ---- auto: node WITHOUT openclaw — must NOT inject ----
		{
			"auto/node random.js",
			NodeCompatAuto,
			[]string{"node", "/usr/local/bin/random.js"},
			false,
		},
		{
			"auto/node -e inline",
			NodeCompatAuto,
			[]string{"node", "-e", "console.log('hi')"},
			false,
		},
		{
			"auto/node hermes.js (other agent, no openclaw)",
			NodeCompatAuto,
			[]string{"node", "/usr/lib/node_modules/hermes-agent/dist/index.js"},
			false,
		},
		{
			"auto/node with substring openclawpaths (no slash-bounded match)",
			NodeCompatAuto,
			// "/foo/openclawish/bar.js" must NOT match — hint requires "/openclaw/"
			[]string{"node", "/foo/openclawish/bar.js"},
			false,
		},

		// ---- auto: other binaries ----
		{"auto/codex (TLS-bridge concern, not Node compat)", NodeCompatAuto, []string{"codex"}, false},
		{"auto/claude", NodeCompatAuto, []string{"claude"}, false},
		{"auto/bash", NodeCompatAuto, []string{"bash", "-c", "echo hi"}, false},

		// ---- zero-value mode = auto ----
		{"empty mode falls back to auto/openclaw", NodeCompatMode(""), []string{"openclaw"}, true},
		{"empty mode + non-openclaw is false", NodeCompatMode(""), []string{"node", "/tmp/random.js"}, false},
		{"empty mode + node-wrapped openclaw is true", NodeCompatMode(""), []string{"node", "/usr/lib/node_modules/openclaw/dist/index.js"}, true},

		// ---- edge cases ----
		{"empty args", NodeCompatAuto, []string{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nodeCompatEnabled(tc.mode, tc.args); got != tc.want {
				t.Errorf("nodeCompatEnabled(%q, %v) = %v, want %v", tc.mode, tc.args, got, tc.want)
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
