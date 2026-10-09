package rules

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/DevPooks/repodoctor/internal/model"
)

type secretPattern struct {
	name  string
	regex *regexp.Regexp
	group int
}

var secretPatterns = []secretPattern{
	{"private key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`), 0},
	{"AWS access key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), 0},
	{"GitHub token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`), 0},
	{"API token assignment", regexp.MustCompile(`(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|password)\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{16,})`), 1},
}

func Secrets(root string, ignoredPaths []string) ([]model.Finding, error) {
	var findings []model.Finding
	err := walkTextFiles(root, ignoredPaths, func(path, relative string, data []byte) error {
		for index, line := range bytes.Split(data, []byte("\n")) {
			for _, pattern := range secretPatterns {
				match := pattern.regex.FindSubmatch(line)
				if match == nil {
					continue
				}
				value := string(match[pattern.group])
				if looksLikePlaceholder(value) {
					continue
				}
				rule := model.Rules["RD-SEC-007"]
				findings = append(findings, model.Finding{Code: rule.Code, Title: rule.Name,
					Description: pattern.name + ": " + redact(value), Category: "security", Severity: model.SeverityHigh,
					Confidence: model.ConfidenceHigh, File: relative, Line: index + 1, Source: "local static inspection",
					Recommendation: rule.Action})
			}
		}
		return nil
	})
	return findings, err
}

func redact(value string) string {
	if strings.Contains(value, "PRIVATE KEY") {
		return "-----BEGIN **** PRIVATE KEY-----"
	}
	if len(value) <= 8 {
		return "****"
	}
	return value[:3] + "-****" + value[len(value)-4:]
}

func looksLikePlaceholder(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"example", "placeholder", "change-me", "changeme", "your-", "test-token", "dummy"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
