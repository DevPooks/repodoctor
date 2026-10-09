package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/DevPooks/repodoctor/internal/model"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Ignore struct {
		Packages []string `yaml:"packages"`
		Paths    []string `yaml:"paths"`
	} `yaml:"ignore"`
	Rules struct {
		LargeFileLines        int `yaml:"large_file_lines"`
		PackageAgeWarningDays int `yaml:"package_age_warning_days"`
	} `yaml:"rules"`
	Security struct {
		OSV              bool `yaml:"osv"`
		RegistryMetadata bool `yaml:"registry_metadata"`
		SecretScan       bool `yaml:"secret_scan"`
	} `yaml:"security"`
	SeverityOverrides map[string]model.Severity `yaml:"severity_overrides"`
	IgnoreFindings    []string                  `yaml:"ignore_findings"`
}

func Default() Config {
	var cfg Config
	cfg.Rules.LargeFileLines = 500
	cfg.Rules.PackageAgeWarningDays = 14
	cfg.Security.OSV = true
	cfg.Security.RegistryMetadata = true
	cfg.Security.SecretScan = true
	cfg.SeverityOverrides = map[string]model.Severity{}
	return cfg
}

func Load(root string) (Config, error) {
	cfg := Default()
	path := filepath.Join(root, ".repodoctor.yml")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse .repodoctor.yml: %w", err)
	}
	if cfg.Rules.LargeFileLines < 1 || cfg.Rules.PackageAgeWarningDays < 0 {
		return cfg, errors.New("invalid .repodoctor.yml rule threshold")
	}
	for code, severity := range cfg.SeverityOverrides {
		if _, ok := model.Rules[code]; !ok {
			return cfg, fmt.Errorf("unknown severity override code %s", code)
		}
		if !validSeverity(severity) {
			return cfg, fmt.Errorf("invalid severity %q for %s", severity, code)
		}
	}
	return cfg, nil
}

func validSeverity(severity model.Severity) bool {
	switch severity {
	case model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo:
		return true
	default:
		return false
	}
}
