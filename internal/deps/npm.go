package deps

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/DevPooks/repodoctor/internal/model"
)

type packageJSON struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

func parsePackageJSON(path string) ([]model.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var manifest packageJSON
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	var result []model.Dependency
	for _, group := range []map[string]string{manifest.Dependencies, manifest.DevDependencies, manifest.OptionalDependencies} {
		for name, value := range group {
			sourceType := classifySource(value)
			version := value
			if sourceType != model.SourceRegistry {
				version = ""
			}
			result = append(result, model.Dependency{
				Name: name, Version: version, Constraint: value, Ecosystem: "npm", Direct: true,
				SourceType: sourceType, Source: sourceValue(value, sourceType), Manifest: filepath.Base(path),
			})
		}
	}
	return result, nil
}

type packageLock struct {
	Packages map[string]struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Resolved string `json:"resolved"`
		Link     bool   `json:"link"`
	} `json:"packages"`
}

func parsePackageLock(path string) ([]model.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock packageLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	var result []model.Dependency
	for packagePath, entry := range lock.Packages {
		if packagePath == "" || entry.Link {
			continue
		}
		name := entry.Name
		if name == "" {
			index := strings.LastIndex(packagePath, "node_modules/")
			if index >= 0 {
				name = packagePath[index+len("node_modules/"):]
			}
		}
		if name == "" || entry.Version == "" {
			continue
		}
		sourceType := model.SourceRegistry
		if entry.Resolved != "" {
			parsed, parseErr := url.Parse(entry.Resolved)
			if parseErr == nil && parsed.Host != "" && parsed.Host != "registry.npmjs.org" {
				sourceType = model.SourceHTTP
			}
		}
		result = append(result, model.Dependency{
			Name: name, Version: entry.Version, Ecosystem: "npm", Direct: directNPMPath(packagePath),
			SourceType: sourceType, Source: entry.Resolved, Manifest: filepath.Base(path),
		})
	}
	return result, nil
}

func directNPMPath(path string) bool {
	trimmed := strings.TrimPrefix(path, "node_modules/")
	if strings.HasPrefix(trimmed, "@") {
		return strings.Count(trimmed, "/") == 1
	}
	return !strings.Contains(trimmed, "/node_modules/") && !strings.Contains(trimmed, "/")
}

func classifySource(value string) model.SourceType {
	lower := strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.HasPrefix(lower, "git+"), strings.HasPrefix(lower, "git://"), strings.HasPrefix(lower, "ssh://"):
		return model.SourceGit
	case strings.HasPrefix(lower, "github:"), strings.Contains(lower, "github.com/"):
		return model.SourceGitHub
	case strings.HasPrefix(lower, "http://"), strings.HasPrefix(lower, "https://"):
		return model.SourceHTTP
	case strings.HasPrefix(lower, "file:"), strings.HasPrefix(lower, "link:"), strings.HasPrefix(lower, "../"), strings.HasPrefix(lower, "./"):
		return model.SourceLocal
	default:
		return model.SourceRegistry
	}
}

func sourceValue(value string, sourceType model.SourceType) string {
	if sourceType == model.SourceRegistry {
		return ""
	}
	return value
}
