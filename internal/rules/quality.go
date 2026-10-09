package rules

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/DevPooks/repodoctor/internal/model"
)

var todoPattern = regexp.MustCompile(`(?i)(//|#|/\*|<!--|--)\s*(TODO|FIXME)\b`)

func Quality(root string, largeFileLines int, ignoredPaths []string) ([]model.Finding, error) {
	var findings []model.Finding
	err := walkTextFiles(root, ignoredPaths, func(path, relative string, data []byte) error {
		if generatedOrLock(relative, data) {
			return nil
		}
		lines := bytes.Split(data, []byte("\n"))
		if isSourceFile(relative) && len(lines) > largeFileLines {
			rule := model.Rules["RD-QUALITY-001"]
			findings = append(findings, model.Finding{Code: rule.Code, Title: rule.Name,
				Description: rule.Explanation, Category: "quality", Severity: model.SeverityLow,
				Confidence: model.ConfidenceHigh, File: relative, Source: "static inspection",
				Recommendation: rule.Action})
		}
		for index, line := range lines {
			if todoPattern.Match(line) {
				rule := model.Rules["RD-QUALITY-002"]
				findings = append(findings, model.Finding{Code: rule.Code, Title: rule.Name,
					Description: strings.TrimSpace(string(line)), Category: "quality", Severity: model.SeverityInfo,
					Confidence: model.ConfidenceHigh, File: relative, Line: index + 1, Source: "static inspection",
					Recommendation: rule.Action})
			}
		}
		return nil
	})
	return findings, err
}

func generatedOrLock(relative string, data []byte) bool {
	name := strings.ToLower(filepath.Base(relative))
	if strings.HasSuffix(name, ".lock") || name == "package-lock.json" || name == "npm-shrinkwrap.json" || name == "go.sum" {
		return true
	}
	prefix := string(data)
	if len(prefix) > 300 {
		prefix = prefix[:300]
	}
	return strings.Contains(strings.ToLower(prefix), "code generated") && strings.Contains(strings.ToLower(prefix), "do not edit")
}

func isSourceFile(relative string) bool {
	switch strings.ToLower(filepath.Ext(relative)) {
	case ".go", ".java", ".py", ".js", ".jsx", ".ts", ".tsx", ".rs", ".rb", ".php", ".cs", ".cpp", ".c", ".h", ".kt":
		return true
	default:
		return false
	}
}
