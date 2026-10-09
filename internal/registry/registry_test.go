package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DevPooks/repodoctor/internal/model"
)

func TestMissingSimilarPackageIsAHeuristicFinding(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	client := NewClient()
	client.HTTP = server.Client()
	client.NPMBaseURL = server.URL
	client.PyPIBaseURL = server.URL
	client.Concurrency = 1
	findings, status := client.Check(context.Background(), []model.Dependency{{
		Name: "lodahs", Version: "1.0.0", Ecosystem: "npm", Direct: true, SourceType: model.SourceRegistry,
	}}, 14)
	if status != model.LookupComplete || len(findings) != 1 {
		t.Fatalf("unexpected result: %s %#v", status, findings)
	}
	if findings[0].Code != "RD-SEC-004" || findings[0].Severity != model.SeverityMedium {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestEditDistance(t *testing.T) {
	if got := editDistance("expresss", "express"); got != 1 {
		t.Fatalf("expected distance 1, got %d", got)
	}
	if got := editDistance("reqeusts", "requests"); got != 2 {
		t.Fatalf("expected distance 2, got %d", got)
	}
}
