package advisory

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DevPooks/repodoctor/internal/model"
)

func TestLookupDistinguishesVulnerabilityAndMaliciousRecord(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-demo","summary":"Fixture vulnerability","database_specific":{"severity":"HIGH"}}]},{"vulns":[{"id":"MAL-2026-DEMO","summary":"Synthetic malicious-package record"}]}]}`))
	}))
	defer server.Close()
	client := &OSVClient{BaseURL: server.URL, HTTP: server.Client(), Retries: 0}
	dependencies := []model.Dependency{
		{Name: "example-a", Version: "1.0.0", Ecosystem: "npm", SourceType: model.SourceRegistry},
		{Name: "example-b", Version: "2.0.0", Ecosystem: "PyPI", SourceType: model.SourceRegistry},
	}
	findings, status, err := client.Lookup(context.Background(), dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if status != model.LookupComplete || len(findings) != 2 {
		t.Fatalf("unexpected lookup result: %s %#v", status, findings)
	}
	if findings[0].Code != "RD-SEC-001" || findings[1].Code != "RD-SEC-002" || findings[1].Severity != model.SeverityCritical {
		t.Fatalf("records were not classified correctly: %#v", findings)
	}
}

func TestLookupReportsUnavailableOnTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		time.Sleep(50 * time.Millisecond)
	}))
	defer server.Close()
	client := &OSVClient{BaseURL: server.URL, HTTP: &http.Client{Timeout: 5 * time.Millisecond}, Retries: 0}
	_, status, err := client.Lookup(context.Background(), []model.Dependency{{Name: "a", Version: "1.0.0", Ecosystem: "npm", SourceType: model.SourceRegistry}})
	if err == nil || status != model.LookupUnavailable {
		t.Fatalf("expected unavailable status, got %s, %v", status, err)
	}
}
