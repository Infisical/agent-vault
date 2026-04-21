package mitm

import (
	"net/http"
	"testing"
)

func TestIsLoopbackPeer(t *testing.T) {
	cases := []struct {
		remote string
		want   bool
	}{
		{"127.0.0.1:54321", true},
		{"127.1.2.3:54321", true},
		{"[::1]:54321", true},
		{"10.0.0.5:54321", false},
		{"172.17.0.1:54321", false},
		{"203.0.113.9:54321", false},
		{"[2001:db8::1]:54321", false},
		{"", false},
		{"not-an-address", false},
	}
	for _, tc := range cases {
		r := &http.Request{RemoteAddr: tc.remote}
		if got := isLoopbackPeer(r); got != tc.want {
			t.Errorf("isLoopbackPeer(%q) = %v, want %v", tc.remote, got, tc.want)
		}
	}
}
