package rules

import (
	"strings"

	"github.com/DevPooks/repodoctor/internal/model"
)

func Dependencies(dependencies []model.Dependency, ignoredPackages []string) []model.Finding {
	ignored := map[string]bool{}
	for _, name := range ignoredPackages {
		ignored[strings.ToLower(name)] = true
	}
	var findings []model.Finding
	for _, dependency := range dependencies {
		if ignored[strings.ToLower(dependency.Name)] {
			continue
		}
		if dependency.SourceType != model.SourceRegistry {
			rule := model.Rules["RD-SEC-005"]
			severity := model.SeverityMedium
			description := rule.Explanation
			if dependency.SourceType == model.SourceLocal && (strings.Contains(dependency.Source, "../") || strings.HasPrefix(dependency.Source, "/")) {
				severity = model.SeverityHigh
				description = "Dependency points to a local path outside the repository boundary."
			}
			findings = append(findings, model.Finding{Code: rule.Code, Title: rule.Name,
				Description: description, Category: "supply-chain", Severity: severity, Confidence: model.ConfidenceHigh,
				File: dependency.Manifest, Line: dependency.Line, PackageName: dependency.Name,
				PackageVersion: dependency.Constraint, Ecosystem: dependency.Ecosystem,
				Source: string(dependency.SourceType), ReferenceURL: safeReference(dependency.Source), Recommendation: rule.Action})
		}
		if dependency.Direct && dependency.SourceType == model.SourceRegistry && !dependency.HasExactVersion() {
			rule := model.Rules["RD-SEC-006"]
			findings = append(findings, model.Finding{Code: rule.Code, Title: rule.Name,
				Description: rule.Explanation, Category: "supply-chain", Severity: model.SeverityMedium,
				Confidence: model.ConfidenceHigh, File: dependency.Manifest, Line: dependency.Line,
				PackageName: dependency.Name, PackageVersion: dependency.Constraint, Ecosystem: dependency.Ecosystem,
				Source: "manifest", Recommendation: rule.Action})
		}
	}
	return findings
}

func safeReference(source string) string {
	if strings.HasPrefix(source, "https://") || strings.HasPrefix(source, "http://") {
		return source
	}
	return ""
}
