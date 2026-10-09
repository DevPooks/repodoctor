package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/DevPooks/repodoctor/internal/model"
)

func JSON(writer io.Writer, value model.Report) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func Text(writer io.Writer, value model.Report, concise bool) error {
	if concise {
		_, err := fmt.Fprintf(writer, "RepoDoctor: %d critical, %d high, %d medium, %d low (%d dependencies, %d suppressed)\n",
			value.Summary.Critical, value.Summary.High, value.Summary.Medium, value.Summary.Low,
			value.DependenciesScanned, value.SuppressedFindingCount)
		return err
	}
	fmt.Fprintln(writer, "RepoDoctor")
	fmt.Fprintln(writer, "Scanning:", value.Repository)
	fmt.Fprintln(writer)
	sections := []struct {
		name       string
		categories map[string]bool
	}{
		{"Supply Chain & Security", map[string]bool{"security": true, "supply-chain": true}},
		{"Repository Health", map[string]bool{"health": true}},
		{"Repository Quality", map[string]bool{"quality": true}},
	}
	for _, section := range sections {
		fmt.Fprintln(writer, section.name)
		fmt.Fprintln(writer, strings.Repeat("─", len([]rune(section.name))+8))
		count := 0
		for _, finding := range value.Findings {
			if !section.categories[finding.Category] {
				continue
			}
			count++
			location := finding.File
			if finding.Line > 0 {
				location = fmt.Sprintf("%s:%d", location, finding.Line)
			}
			packageLabel := finding.PackageName
			if finding.PackageVersion != "" {
				packageLabel += "@" + finding.PackageVersion
			}
			label := strings.TrimSpace(strings.Join([]string{location, packageLabel}, " "))
			fmt.Fprintf(writer, "%s %s [%s]", severitySymbol(finding.Severity), finding.Title, finding.Code)
			if label != "" {
				fmt.Fprintf(writer, " — %s", label)
			}
			fmt.Fprintln(writer)
			fmt.Fprintf(writer, "  %s\n", finding.Description)
			fmt.Fprintf(writer, "  Fix: %s\n", finding.Recommendation)
			if finding.ReferenceURL != "" {
				fmt.Fprintf(writer, "  Reference: %s\n", finding.ReferenceURL)
			}
		}
		if count == 0 {
			fmt.Fprintln(writer, "✓ No findings in this category.")
		}
		fmt.Fprintln(writer)
	}
	fmt.Fprintf(writer, "Dependencies scanned: %d\n", value.DependenciesScanned)
	if value.VulnerabilityLookup == model.LookupUnavailable {
		fmt.Fprintln(writer, "Vulnerability lookup unavailable; results are unknown, not safe.")
	} else if value.VulnerabilityLookup == model.LookupComplete {
		fmt.Fprintln(writer, "Vulnerability lookup completed.")
	}
	if value.RegistryLookup == model.LookupUnavailable {
		fmt.Fprintln(writer, "Registry metadata lookup unavailable or incomplete.")
	}
	fmt.Fprintln(writer)
	fmt.Fprintln(writer, "Summary")
	fmt.Fprintf(writer, "Critical: %d\nHigh:     %d\nMedium:   %d\nLow:      %d\nInfo:     %d\n",
		value.Summary.Critical, value.Summary.High, value.Summary.Medium, value.Summary.Low, value.Summary.Info)
	fmt.Fprintf(writer, "Suppressed: %d\nExit code:  %d\n", value.SuppressedFindingCount, model.ExitCode(value))
	return nil
}

func severitySymbol(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical, model.SeverityHigh:
		return "✗"
	case model.SeverityMedium, model.SeverityLow:
		return "⚠"
	default:
		return "•"
	}
}
