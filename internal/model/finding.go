package model

import "fmt"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

type Finding struct {
	Code           string     `json:"code"`
	Title          string     `json:"title"`
	Description    string     `json:"description"`
	Category       string     `json:"category"`
	Severity       Severity   `json:"severity"`
	Confidence     Confidence `json:"confidence"`
	File           string     `json:"file,omitempty"`
	Line           int        `json:"line,omitempty"`
	PackageName    string     `json:"package_name,omitempty"`
	PackageVersion string     `json:"package_version,omitempty"`
	Ecosystem      string     `json:"ecosystem,omitempty"`
	Source         string     `json:"source,omitempty"`
	ReferenceURL   string     `json:"reference_url,omitempty"`
	Recommendation string     `json:"recommendation"`
}

func (f Finding) SuppressionKey() string {
	if f.PackageName != "" {
		return fmt.Sprintf("%s:%s", f.Code, f.PackageName)
	}
	if f.File != "" {
		return fmt.Sprintf("%s:%s", f.Code, f.File)
	}
	return f.Code
}

func SeverityRank(severity Severity) int {
	switch severity {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	default:
		return 1
	}
}
