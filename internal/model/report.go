package model

import "time"

type LookupStatus string

const (
	LookupNotRequested LookupStatus = "not_requested"
	LookupComplete     LookupStatus = "complete"
	LookupUnavailable  LookupStatus = "unavailable"
)

type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type Report struct {
	SchemaVersion          string       `json:"schema_version"`
	Repository             string       `json:"repository"`
	ScannedAt              time.Time    `json:"scanned_at"`
	DurationMS             int64        `json:"duration_ms"`
	DependenciesScanned    int          `json:"dependencies_scanned"`
	VulnerabilityLookup    LookupStatus `json:"vulnerability_lookup"`
	RegistryLookup         LookupStatus `json:"registry_lookup"`
	SuppressedFindingCount int          `json:"suppressed_finding_count"`
	Summary                Summary      `json:"summary"`
	Findings               []Finding    `json:"findings"`
	Dependencies           []Dependency `json:"dependencies,omitempty"`
}

func Summarize(findings []Finding) Summary {
	var summary Summary
	for _, finding := range findings {
		switch finding.Severity {
		case SeverityCritical:
			summary.Critical++
		case SeverityHigh:
			summary.High++
		case SeverityMedium:
			summary.Medium++
		case SeverityLow:
			summary.Low++
		default:
			summary.Info++
		}
	}
	return summary
}

func ExitCode(report Report) int {
	if report.Summary.Critical > 0 || report.Summary.High > 0 {
		return 2
	}
	if report.Summary.Medium > 0 || report.Summary.Low > 0 {
		return 1
	}
	return 0
}
