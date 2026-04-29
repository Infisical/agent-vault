package inspect

import (
	"strings"
	"testing"
)

func TestDiagnosePlainHTTPOnMITM(t *testing.T) {
	d := Diagnose(RequestLog{Ingress: "mitm", Method: "POST", Status: 405, ErrorCode: "method_not_supported"})
	if !strings.Contains(d.Summary, "Plain HTTP") {
		t.Fatalf("expected plain HTTP diagnosis, got %q", d.Summary)
	}
}

func TestDiagnoseNoMatchedService(t *testing.T) {
	d := Diagnose(RequestLog{Host: "api.example.com", Status: 403})
	if !strings.Contains(d.Summary, "No configured service") {
		t.Fatalf("expected no-service diagnosis, got %q", d.Summary)
	}
}

func TestDiagnoseAuthRejected(t *testing.T) {
	d := Diagnose(RequestLog{
		MatchedService: "api.anthropic.com",
		CredentialKeys: []string{"ANTHROPIC_API_KEY"},
		Status:         401,
	})
	if !strings.Contains(d.Summary, "rejected") {
		t.Fatalf("expected auth rejection diagnosis, got %q", d.Summary)
	}
	if len(d.SuggestedNext) == 0 {
		t.Fatal("expected suggestions")
	}
}

func TestDiagnoseBatchSkipsHealthyLogs(t *testing.T) {
	got := DiagnoseBatch([]RequestLog{
		{ID: 1, MatchedService: "api.example.com", Status: 200},
		{ID: 2, MatchedService: "api.example.com", Status: 500},
	})
	if len(got) != 1 || got[0].Log.ID != 2 {
		t.Fatalf("expected only failed log, got %+v", got)
	}
}

func TestDiagnoseStripsControlCharactersFromDetails(t *testing.T) {
	d := Diagnose(RequestLog{Host: "api.example.com/\x1b[31m", Status: 403})
	if strings.Contains(d.Details[0], "\x1b") {
		t.Fatalf("expected control character to be stripped, got %q", d.Details[0])
	}
}
