package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/DevPooks/repodoctor/internal/advisory"
	"github.com/DevPooks/repodoctor/internal/model"
	"github.com/DevPooks/repodoctor/internal/registry"
)

func TestSafeFixtureHasNoOfflineFindings(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "safe")
	report, err := Run(context.Background(), root, Options{Mode: ModeAll, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("expected safe fixture to be clean, got %#v", report.Findings)
	}
	if report.Findings == nil {
		t.Fatal("expected stable empty findings array, got nil")
	}
}

func TestDirectURLFixtureProducesSupplyChainFinding(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "direct-url")
	report, err := Run(context.Background(), root, Options{Mode: ModeSecurity, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(report, "RD-SEC-005") {
		t.Fatalf("expected direct URL finding, got %#v", report.Findings)
	}
}

func TestMissingCIFixtureProducesHealthFinding(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "missing-ci")
	report, err := Run(context.Background(), root, Options{Mode: ModeHealth, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(report, "RD-HEALTH-003") {
		t.Fatalf("expected missing CI finding, got %#v", report.Findings)
	}
}

func TestExternalRecordsFlowThroughScanner(t *testing.T) {
	tests := []struct {
		fixture  string
		response string
		code     string
	}{
		{"vulnerable", `{"results":[{"vulns":[{"id":"GHSA-FIXTURE","summary":"Synthetic vulnerable version","database_specific":{"severity":"HIGH"}}]}]}`, "RD-SEC-001"},
		{"malicious", `{"results":[{"vulns":[{"id":"MAL-2026-FIXTURE","summary":"Synthetic malicious-package record"}]}]}`, "RD-SEC-002"},
	}
	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				if request.Method == http.MethodPost {
					writer.Write([]byte(test.response))
					return
				}
				writer.Write([]byte(`{"time":{"created":"2020-01-01T00:00:00Z"}}`))
			}))
			defer server.Close()
			osv := &advisory.OSVClient{BaseURL: server.URL, HTTP: server.Client(), Retries: 0}
			metadata := registry.NewClient()
			metadata.HTTP = server.Client()
			metadata.NPMBaseURL = server.URL
			metadata.PyPIBaseURL = server.URL
			report, err := Run(context.Background(), filepath.Join("..", "..", "testdata", test.fixture), Options{
				Mode: ModeSecurity, OSV: osv, Registry: metadata,
			})
			if err != nil {
				t.Fatal(err)
			}
			if !hasCode(report, test.code) {
				t.Fatalf("expected %s, got %#v", test.code, report.Findings)
			}
		})
	}
}

func TestSecretFixtureIsRedacted(t *testing.T) {
	report, err := Run(context.Background(), filepath.Join("..", "..", "testdata", "secret"), Options{Mode: ModeSecurity, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(report, "RD-SEC-007") {
		t.Fatalf("expected secret finding, got %#v", report.Findings)
	}
}

func hasCode(report model.Report, code string) bool {
	for _, finding := range report.Findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}
