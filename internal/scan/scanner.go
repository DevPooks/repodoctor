package scan

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/DevPooks/repodoctor/internal/advisory"
	"github.com/DevPooks/repodoctor/internal/config"
	"github.com/DevPooks/repodoctor/internal/deps"
	"github.com/DevPooks/repodoctor/internal/model"
	"github.com/DevPooks/repodoctor/internal/registry"
	"github.com/DevPooks/repodoctor/internal/rules"
)

type Mode string

const (
	ModeAll      Mode = "all"
	ModeDeps     Mode = "deps"
	ModeSecurity Mode = "security"
	ModeHealth   Mode = "health"
)

type Options struct {
	Mode     Mode
	Offline  bool
	OSV      *advisory.OSVClient
	Registry *registry.Client
}

func Run(ctx context.Context, root string, options Options) (model.Report, error) {
	started := time.Now()
	absolute, err := filepath.Abs(root)
	if err != nil {
		return model.Report{}, err
	}
	cfg, err := config.Load(absolute)
	if err != nil {
		return model.Report{}, err
	}
	report := model.Report{SchemaVersion: "1.0", Repository: absolute, ScannedAt: started.UTC(),
		VulnerabilityLookup: model.LookupNotRequested, RegistryLookup: model.LookupNotRequested,
		Findings: []model.Finding{}}
	var findings []model.Finding
	var dependencies []model.Dependency

	if options.Mode != ModeHealth {
		dependencies, err = deps.Extract(absolute)
		if err != nil {
			return report, err
		}
		dependencies = filterPackages(dependencies, cfg.Ignore.Packages)
		report.Dependencies = dependencies
		report.DependenciesScanned = len(dependencies)
		findings = append(findings, rules.Dependencies(dependencies, cfg.Ignore.Packages)...)
	}
	if options.Mode == ModeAll || options.Mode == ModeHealth {
		healthFindings, healthErr := rules.Health(absolute)
		if healthErr != nil {
			return report, healthErr
		}
		qualityFindings, qualityErr := rules.Quality(absolute, cfg.Rules.LargeFileLines, cfg.Ignore.Paths)
		if qualityErr != nil {
			return report, qualityErr
		}
		findings = append(findings, healthFindings...)
		findings = append(findings, qualityFindings...)
	}
	if options.Mode == ModeAll || options.Mode == ModeSecurity {
		lifecycleFindings, lifecycleErr := rules.LifecycleScripts(absolute)
		if lifecycleErr != nil {
			return report, lifecycleErr
		}
		findings = append(findings, lifecycleFindings...)
		if cfg.Security.SecretScan {
			secretFindings, secretErr := rules.Secrets(absolute, cfg.Ignore.Paths)
			if secretErr != nil {
				return report, secretErr
			}
			findings = append(findings, secretFindings...)
		}
		if !options.Offline && cfg.Security.OSV {
			client := options.OSV
			if client == nil {
				client = advisory.NewOSVClient()
			}
			osvFindings, status, lookupErr := client.Lookup(ctx, dependencies)
			report.VulnerabilityLookup = status
			if lookupErr == nil {
				findings = append(findings, osvFindings...)
			}
		}
		if !options.Offline && cfg.Security.RegistryMetadata {
			client := options.Registry
			if client == nil {
				client = registry.NewClient()
			}
			registryFindings, status := client.Check(ctx, dependencies, cfg.Rules.PackageAgeWarningDays)
			report.RegistryLookup = status
			findings = append(findings, registryFindings...)
		}
	}

	findings, report.SuppressedFindingCount = applyPolicy(findings, cfg)
	if findings == nil {
		findings = []model.Finding{}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := model.SeverityRank(findings[i].Severity), model.SeverityRank(findings[j].Severity)
		if left != right {
			return left > right
		}
		if findings[i].Code != findings[j].Code {
			return findings[i].Code < findings[j].Code
		}
		return findings[i].File < findings[j].File
	})
	report.Findings = findings
	report.Summary = model.Summarize(findings)
	report.DurationMS = time.Since(started).Milliseconds()
	return report, nil
}

func filterPackages(dependencies []model.Dependency, ignored []string) []model.Dependency {
	ignore := map[string]bool{}
	for _, name := range ignored {
		ignore[strings.ToLower(strings.TrimSpace(name))] = true
	}
	result := dependencies[:0]
	for _, dependency := range dependencies {
		if !ignore[strings.ToLower(dependency.Name)] {
			result = append(result, dependency)
		}
	}
	return result
}

func applyPolicy(findings []model.Finding, cfg config.Config) ([]model.Finding, int) {
	ignored := map[string]bool{}
	for _, key := range cfg.IgnoreFindings {
		ignored[key] = true
	}
	result := findings[:0]
	suppressed := 0
	for _, finding := range findings {
		if severity, ok := cfg.SeverityOverrides[finding.Code]; ok {
			finding.Severity = severity
		}
		if ignored[finding.Code] || ignored[finding.SuppressionKey()] {
			suppressed++
			continue
		}
		result = append(result, finding)
	}
	return result, suppressed
}

func ValidateMode(mode Mode) error {
	switch mode {
	case ModeAll, ModeDeps, ModeSecurity, ModeHealth:
		return nil
	default:
		return fmt.Errorf("unsupported scan mode %q", mode)
	}
}
