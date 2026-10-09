package deps

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/DevPooks/repodoctor/internal/model"
)

var requirementPattern = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^]]+\])?\s*(.*)$`)

func parseRequirements(path string) ([]model.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var result []model.Dependency
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if index := strings.Index(line, " #"); index >= 0 {
			line = strings.TrimSpace(line[:index])
		}
		dependency, ok := parsePythonRequirement(line, filepath.Base(path), lineNumber)
		if ok {
			result = append(result, dependency)
		}
	}
	return result, scanner.Err()
}

func parsePythonRequirement(value, manifest string, line int) (model.Dependency, bool) {
	if parts := strings.SplitN(value, " @ ", 2); len(parts) == 2 {
		return model.Dependency{Name: normalizePythonName(parts[0]), Ecosystem: "PyPI", Direct: true,
			SourceType: classifySource(parts[1]), Source: parts[1], Constraint: parts[1], Manifest: manifest, Line: line}, true
	}
	match := requirementPattern.FindStringSubmatch(value)
	if match == nil {
		return model.Dependency{}, false
	}
	name := normalizePythonName(match[1])
	constraint := strings.TrimSpace(strings.SplitN(match[2], ";", 2)[0])
	version := ""
	if strings.HasPrefix(constraint, "==") && !strings.ContainsAny(strings.TrimPrefix(constraint, "=="), "*,") {
		version = strings.TrimSpace(strings.TrimPrefix(constraint, "=="))
	} else if constraint != "" {
		version = constraint
	}
	return model.Dependency{Name: name, Version: version, Constraint: constraint, Ecosystem: "PyPI", Direct: true,
		SourceType: model.SourceRegistry, Manifest: manifest, Line: line}, true
}

func normalizePythonName(name string) string {
	return strings.ToLower(strings.NewReplacer("_", "-", ".", "-").Replace(strings.TrimSpace(name)))
}
