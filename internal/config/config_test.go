package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMergesFileWithDefaults(t *testing.T) {
	root := t.TempDir()
	data := []byte("rules:\n  large_file_lines: 250\n  package_age_warning_days: 7\nsecurity:\n  osv: true\n  registry_metadata: false\n  secret_scan: true\nseverity_overrides:\n  RD-HEALTH-003: low\n")
	if err := os.WriteFile(filepath.Join(root, ".repodoctor.yml"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if config.Rules.LargeFileLines != 250 || config.Rules.PackageAgeWarningDays != 7 || config.Security.RegistryMetadata {
		t.Fatalf("config not loaded: %#v", config)
	}
}

func TestLoadRejectsUnknownFindingCode(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, ".repodoctor.yml"), []byte("severity_overrides:\n  RD-NOPE-999: low\n"), 0o600)
	if _, err := Load(root); err == nil {
		t.Fatal("expected validation error")
	}
}
