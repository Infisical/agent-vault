package infisical

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetProjectSlug(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"workspace":{"id":"pid-1","slug":"my-proj-abc","name":"My Proj"}}`))
	}))
	defer srv.Close()

	slug, err := getProjectSlug(context.Background(), srv.Client(), srv.URL, "tok-123", "pid-1")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if slug != "my-proj-abc" {
		t.Fatalf("got slug %q", slug)
	}
	if gotAuth != "Bearer tok-123" {
		t.Fatalf("got auth header %q", gotAuth)
	}
	if gotPath != "/api/v1/workspace/pid-1" {
		t.Fatalf("got path %q", gotPath)
	}
}

func TestGetProjectSlug_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Project with slug 'pid-1' not found"}`))
	}))
	defer srv.Close()

	if _, err := getProjectSlug(context.Background(), srv.Client(), srv.URL, "tok", "pid-1"); err == nil {
		t.Fatal("expected error on 404")
	}
}
