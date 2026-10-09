package rules

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/DevPooks/repodoctor/internal/model"
)

var riskyScript = regexp.MustCompile(`(?i)(curl|wget|powershell|bash\s+-c|sh\s+-c|base64\s+(-d|--decode)|chmod\s+\+x|Invoke-WebRequest|https?://)`)

func LifecycleScripts(root string) ([]model.Finding, error) {
	path := filepath.Join(root, "package.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	var findings []model.Finding
	for _, name := range []string{"preinstall", "install", "postinstall", "prepare"} {
		command, ok := manifest.Scripts[name]
		if !ok || !riskyScript.MatchString(command) {
			continue
		}
		severity := model.SeverityMedium
		matches := riskyScript.FindAllString(command, -1)
		if len(matches) >= 2 || strings.Contains(strings.ToLower(command), "base64") {
			severity = model.SeverityHigh
		}
		rule := model.Rules["RD-SEC-003"]
		findings = append(findings, model.Finding{Code: rule.Code, Title: rule.Name,
			Description: "npm " + name + " script contains review-worthy commands: " + strings.Join(matches, ", "),
			Category:    "supply-chain", Severity: severity, Confidence: model.ConfidenceHigh,
			File: "package.json", Source: "static script inspection", Recommendation: rule.Action})
	}
	return findings, nil
}
