package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHopTokenRejectedOnControlPlane(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/discover", nil)
	req.Header.Set("Authorization", "Bearer av_cont_eyJhbGciOiJIUzI1NiJ9.eyJraW5kIjoiY29udCJ9.sig")
	rr := httptest.NewRecorder()
	srv.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("control plane accepted a hop token")
	}).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}
