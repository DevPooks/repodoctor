package advisory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/DevPooks/repodoctor/internal/model"
)

type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

type OSVClient struct {
	BaseURL string
	HTTP    Doer
	Retries int
}

func NewOSVClient() *OSVClient {
	return &OSVClient{BaseURL: "https://api.osv.dev", HTTP: &http.Client{Timeout: 12 * time.Second}, Retries: 2}
}

type batchRequest struct {
	Queries []query `json:"queries"`
}
type query struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}
type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}
type batchResponse struct {
	Results []struct {
		Vulns []vulnerability `json:"vulns"`
	} `json:"results"`
}
type vulnerability struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific map[string]any `json:"database_specific"`
	References       []struct {
		URL string `json:"url"`
	} `json:"references"`
}

func (client *OSVClient) Lookup(ctx context.Context, dependencies []model.Dependency) ([]model.Finding, model.LookupStatus, error) {
	exact := make([]model.Dependency, 0, len(dependencies))
	request := batchRequest{}
	for _, dependency := range dependencies {
		if !dependency.HasExactVersion() {
			continue
		}
		ecosystem := osvEcosystem(dependency.Ecosystem)
		if ecosystem == "" {
			continue
		}
		exact = append(exact, dependency)
		request.Queries = append(request.Queries, query{Package: osvPackage{Name: dependency.Name, Ecosystem: ecosystem}, Version: dependency.Version})
	}
	if len(request.Queries) == 0 {
		return nil, model.LookupNotRequested, nil
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, model.LookupUnavailable, err
	}
	var response batchResponse
	if err := client.postWithRetry(ctx, "/v1/querybatch", body, &response); err != nil {
		return nil, model.LookupUnavailable, err
	}
	if len(response.Results) != len(exact) {
		return nil, model.LookupUnavailable, errors.New("OSV returned an incomplete batch response")
	}
	var findings []model.Finding
	for index, result := range response.Results {
		dependency := exact[index]
		for _, vulnerability := range result.Vulns {
			malicious := strings.HasPrefix(strings.ToUpper(vulnerability.ID), "MAL-")
			code := "RD-SEC-001"
			severity := osvSeverity(vulnerability)
			if malicious {
				code = "RD-SEC-002"
				severity = model.SeverityCritical
			}
			rule := model.Rules[code]
			description := strings.TrimSpace(vulnerability.Summary)
			if description == "" {
				description = rule.Explanation
			}
			finding := model.Finding{Code: code, Title: rule.Name, Description: description,
				Category: "supply-chain", Severity: severity, Confidence: model.ConfidenceHigh,
				File: dependency.Manifest, PackageName: dependency.Name, PackageVersion: dependency.Version,
				Ecosystem: dependency.Ecosystem, Source: "OSV / OpenSSF", Recommendation: rule.Action}
			if len(vulnerability.References) > 0 {
				finding.ReferenceURL = vulnerability.References[0].URL
			} else {
				finding.ReferenceURL = "https://osv.dev/vulnerability/" + vulnerability.ID
			}
			findings = append(findings, finding)
		}
	}
	return findings, model.LookupComplete, nil
}

func (client *OSVClient) postWithRetry(ctx context.Context, path string, body []byte, target any) error {
	var lastErr error
	for attempt := 0; attempt <= client.Retries; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(client.BaseURL, "/")+path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("User-Agent", "RepoDoctor/0.1")
		response, err := client.HTTP.Do(request)
		if err != nil {
			lastErr = err
		} else {
			data, readErr := io.ReadAll(io.LimitReader(response.Body, 4<<20))
			response.Body.Close()
			if readErr == nil && response.StatusCode == http.StatusOK {
				return json.Unmarshal(data, target)
			}
			if readErr != nil {
				lastErr = readErr
			} else {
				lastErr = fmt.Errorf("OSV returned HTTP %d", response.StatusCode)
			}
			if response.StatusCode < 500 && response.StatusCode != http.StatusTooManyRequests {
				return lastErr
			}
		}
		if attempt < client.Retries {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt+1) * 250 * time.Millisecond):
			}
		}
	}
	return lastErr
}

func osvEcosystem(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	case "go":
		return "Go"
	default:
		return ""
	}
}

func osvSeverity(vulnerability vulnerability) model.Severity {
	if value, ok := vulnerability.DatabaseSpecific["severity"].(string); ok {
		switch strings.ToLower(value) {
		case "critical":
			return model.SeverityCritical
		case "high":
			return model.SeverityHigh
		case "medium", "moderate":
			return model.SeverityMedium
		case "low":
			return model.SeverityLow
		}
	}
	for _, entry := range vulnerability.Severity {
		if score, err := strconv.ParseFloat(entry.Score, 64); err == nil {
			switch {
			case score >= 9:
				return model.SeverityCritical
			case score >= 7:
				return model.SeverityHigh
			case score >= 4:
				return model.SeverityMedium
			default:
				return model.SeverityLow
			}
		}
	}
	return model.SeverityHigh
}
