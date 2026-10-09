package rules

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/DevPooks/repodoctor/internal/model"
)

func Health(root string) ([]model.Finding, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, entry := range entries {
		names[strings.ToLower(entry.Name())] = true
	}
	var findings []model.Finding
	if !hasPrefix(names, "readme") {
		findings = append(findings, healthFinding("RD-HEALTH-001", model.SeverityMedium))
	}
	if !hasPrefix(names, "license") && !names["copying"] {
		findings = append(findings, healthFinding("RD-HEALTH-002", model.SeverityLow))
	}
	if !names[".gitignore"] {
		findings = append(findings, healthFinding("RD-HEALTH-005", model.SeverityLow))
	}
	if !names["security.md"] {
		findings = append(findings, healthFinding("RD-HEALTH-006", model.SeverityLow))
	}
	if !detectCI(root) {
		findings = append(findings, healthFinding("RD-HEALTH-003", model.SeverityMedium))
	}
	tests, err := detectTests(root)
	if err != nil {
		return nil, err
	}
	if !tests {
		findings = append(findings, healthFinding("RD-HEALTH-004", model.SeverityMedium))
	}
	if tracked, ok := trackedFiles(root); ok {
		for _, file := range tracked {
			lower := strings.ToLower(file)
			base := strings.ToLower(filepath.Base(file))
			if base == ".env" || strings.HasPrefix(base, ".env.") && base != ".env.example" {
				findings = append(findings, model.Finding{Code: "RD-SEC-008", Title: model.Rules["RD-SEC-008"].Name,
					Description: model.Rules["RD-SEC-008"].Explanation, Category: "security", Severity: model.SeverityHigh,
					Confidence: model.ConfidenceHigh, File: file, Source: "git index", Recommendation: model.Rules["RD-SEC-008"].Action})
			}
			if strings.Contains(lower, "node_modules/") || strings.Contains(lower, "/venv/") || strings.Contains(lower, "/.venv/") || strings.HasPrefix(lower, "dist/") || strings.HasPrefix(lower, "build/") {
				findings = append(findings, model.Finding{Code: "RD-HEALTH-007", Title: model.Rules["RD-HEALTH-007"].Name,
					Description: model.Rules["RD-HEALTH-007"].Explanation, Category: "health", Severity: model.SeverityMedium,
					Confidence: model.ConfidenceHigh, File: file, Source: "git index", Recommendation: model.Rules["RD-HEALTH-007"].Action})
			}
		}
	}
	return findings, nil
}

func healthFinding(code string, severity model.Severity) model.Finding {
	rule := model.Rules[code]
	return model.Finding{Code: code, Title: rule.Name, Description: rule.Explanation, Category: "health",
		Severity: severity, Confidence: model.ConfidenceHigh, Recommendation: rule.Action}
}

func hasPrefix(names map[string]bool, prefix string) bool {
	for name := range names {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func detectCI(root string) bool {
	paths := []string{".github/workflows", ".gitlab-ci.yml", "Jenkinsfile", ".circleci/config.yml", "azure-pipelines.yml", "bitbucket-pipelines.yml"}
	for _, path := range paths {
		info, err := os.Stat(filepath.Join(root, path))
		if err == nil && (info.IsDir() || info.Size() > 0) {
			return true
		}
	}
	return false
}

func detectTests(root string) (bool, error) {
	found := false
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || found {
			return err
		}
		if entry.IsDir() && path != root && ignoredDirectories[entry.Name()] {
			return filepath.SkipDir
		}
		name := strings.ToLower(entry.Name())
		if !entry.IsDir() && (strings.HasSuffix(name, "_test.go") || strings.Contains(name, ".test.") || strings.Contains(name, ".spec.") || strings.HasPrefix(name, "test_") || name == "pytest.ini" || strings.HasPrefix(name, "vitest.config") || strings.HasPrefix(name, "jest.config")) {
			found = true
		}
		return nil
	})
	return found, err
}
