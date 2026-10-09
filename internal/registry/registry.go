package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DevPooks/repodoctor/internal/model"
)

type Metadata struct {
	Exists    bool
	CreatedAt time.Time
	URL       string
}

type Client struct {
	HTTP        *http.Client
	Concurrency int
	NPMBaseURL  string
	PyPIBaseURL string
}

func NewClient() *Client {
	return &Client{HTTP: &http.Client{Timeout: 8 * time.Second}, Concurrency: 5,
		NPMBaseURL: "https://registry.npmjs.org", PyPIBaseURL: "https://pypi.org/pypi"}
}

func (client *Client) Check(ctx context.Context, dependencies []model.Dependency, ageWarningDays int) ([]model.Finding, model.LookupStatus) {
	unique := map[string]model.Dependency{}
	for _, dependency := range dependencies {
		if dependency.SourceType == model.SourceRegistry && dependency.Direct && (strings.EqualFold(dependency.Ecosystem, "npm") || strings.EqualFold(dependency.Ecosystem, "pypi")) {
			unique[strings.ToLower(dependency.Ecosystem)+"\x00"+dependency.Name] = dependency
		}
	}
	if len(unique) == 0 {
		return nil, model.LookupNotRequested
	}
	jobs := make(chan model.Dependency)
	results := make(chan struct {
		dependency model.Dependency
		metadata   Metadata
		err        error
	})
	workers := client.Concurrency
	if workers < 1 {
		workers = 1
	}
	var group sync.WaitGroup
	for i := 0; i < workers; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for dependency := range jobs {
				metadata, err := client.lookup(ctx, dependency)
				results <- struct {
					dependency model.Dependency
					metadata   Metadata
					err        error
				}{dependency, metadata, err}
			}
		}()
	}
	go func() {
		for _, dependency := range unique {
			jobs <- dependency
		}
		close(jobs)
		group.Wait()
		close(results)
	}()
	var findings []model.Finding
	failed := 0
	for result := range results {
		if result.err != nil {
			failed++
			continue
		}
		dependency := result.dependency
		if !result.metadata.Exists {
			findings = append(findings, authenticityFinding(dependency, "Package was not found in the expected public registry.", model.SeverityMedium, model.ConfidenceHigh, closestPopular(dependency)))
			continue
		}
		if !result.metadata.CreatedAt.IsZero() && time.Since(result.metadata.CreatedAt) < time.Duration(ageWarningDays)*24*time.Hour {
			findings = append(findings, authenticityFinding(dependency, fmt.Sprintf("Package registry history is less than %d days old.", ageWarningDays), model.SeverityLow, model.ConfidenceMedium, ""))
			continue
		}
		if similar := closestPopular(dependency); similar != "" && editDistance(strings.ToLower(dependency.Name), similar) <= 1 && strings.ToLower(dependency.Name) != similar {
			findings = append(findings, authenticityFinding(dependency, "Package name is very similar to the common package "+similar+".", model.SeverityMedium, model.ConfidenceMedium, similar))
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].PackageName < findings[j].PackageName })
	if failed == len(unique) {
		return findings, model.LookupUnavailable
	}
	if failed > 0 {
		return findings, model.LookupUnavailable
	}
	return findings, model.LookupComplete
}

func (client *Client) lookup(ctx context.Context, dependency model.Dependency) (Metadata, error) {
	if strings.EqualFold(dependency.Ecosystem, "npm") {
		endpoint := strings.TrimRight(client.NPMBaseURL, "/") + "/" + url.PathEscape(dependency.Name)
		var response struct {
			Time map[string]string `json:"time"`
		}
		status, err := client.getJSON(ctx, endpoint, &response)
		if status == http.StatusNotFound {
			return Metadata{Exists: false, URL: endpoint}, nil
		}
		if err != nil {
			return Metadata{}, err
		}
		created, _ := time.Parse(time.RFC3339Nano, response.Time["created"])
		return Metadata{Exists: true, CreatedAt: created, URL: endpoint}, nil
	}
	endpoint := strings.TrimRight(client.PyPIBaseURL, "/") + "/" + url.PathEscape(dependency.Name) + "/json"
	var response struct {
		Releases map[string][]struct {
			Uploaded string `json:"upload_time_iso_8601"`
		} `json:"releases"`
	}
	status, err := client.getJSON(ctx, endpoint, &response)
	if status == http.StatusNotFound {
		return Metadata{Exists: false, URL: endpoint}, nil
	}
	if err != nil {
		return Metadata{}, err
	}
	var earliest time.Time
	for _, files := range response.Releases {
		for _, file := range files {
			created, parseErr := time.Parse(time.RFC3339Nano, file.Uploaded)
			if parseErr == nil && (earliest.IsZero() || created.Before(earliest)) {
				earliest = created
			}
		}
	}
	return Metadata{Exists: true, CreatedAt: earliest, URL: endpoint}, nil
}

func (client *Client) getJSON(ctx context.Context, endpoint string, target any) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("User-Agent", "RepoDoctor/0.1")
	response, err := client.HTTP.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return response.StatusCode, nil
	}
	if response.StatusCode != http.StatusOK {
		return response.StatusCode, fmt.Errorf("registry returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return response.StatusCode, err
	}
	return response.StatusCode, json.Unmarshal(data, target)
}

func authenticityFinding(dependency model.Dependency, description string, severity model.Severity, confidence model.Confidence, similar string) model.Finding {
	if similar != "" && !strings.Contains(description, similar) {
		description += " Closest common package: " + similar + "."
	}
	rule := model.Rules["RD-SEC-004"]
	return model.Finding{Code: rule.Code, Title: rule.Name, Description: description,
		Category: "supply-chain", Severity: severity, Confidence: confidence, File: dependency.Manifest,
		PackageName: dependency.Name, PackageVersion: dependency.Version, Ecosystem: dependency.Ecosystem,
		Source: "npm/PyPI registry metadata", Recommendation: rule.Action}
}

var popularNPM = []string{"axios", "chalk", "commander", "express", "lodash", "moment", "next", "react", "typescript", "vite", "webpack", "zod"}
var popularPyPI = []string{"django", "fastapi", "flask", "numpy", "pandas", "pillow", "pytest", "requests", "sqlalchemy", "urllib3"}

func closestPopular(dependency model.Dependency) string {
	candidates := popularNPM
	if strings.EqualFold(dependency.Ecosystem, "pypi") {
		candidates = popularPyPI
	}
	name := strings.ToLower(dependency.Name)
	best, distance := "", 4
	for _, candidate := range candidates {
		current := editDistance(name, candidate)
		if current < distance {
			best, distance = candidate, current
		}
	}
	if distance <= 2 && best != name {
		return best
	}
	return ""
}

func editDistance(left, right string) int {
	a, b := []rune(left), []rune(right)
	previous := make([]int, len(b)+1)
	for j := range previous {
		previous[j] = j
	}
	for i, x := range a {
		current := make([]int, len(b)+1)
		current[0] = i + 1
		for j, y := range b {
			cost := 0
			if x != y {
				cost = 1
			}
			current[j+1] = min(current[j]+1, previous[j+1]+1, previous[j]+cost)
		}
		previous = current
	}
	return previous[len(b)]
}
