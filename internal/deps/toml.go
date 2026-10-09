package deps

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/DevPooks/repodoctor/internal/model"
)

var quotedValue = regexp.MustCompile(`["']([^"']+)["']`)

func parsePyProject(path string) ([]model.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	section := ""
	inDependencies := false
	var result []model.Dependency
	scanner := bufio.NewScanner(file)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(text, "[") && strings.HasSuffix(text, "]") {
			section = strings.Trim(text, "[]")
			inDependencies = false
			continue
		}
		if section == "project" && strings.HasPrefix(text, "dependencies") {
			inDependencies = true
		}
		if inDependencies {
			for _, match := range quotedValue.FindAllStringSubmatch(text, -1) {
				if dependency, ok := parsePythonRequirement(match[1], filepath.Base(path), line); ok {
					result = append(result, dependency)
				}
			}
			if strings.Contains(text, "]") {
				inDependencies = false
			}
			continue
		}
		if section == "tool.poetry.dependencies" || section == "tool.poetry.group.dev.dependencies" {
			parts := strings.SplitN(text, "=", 2)
			if len(parts) != 2 || strings.TrimSpace(parts[0]) == "python" {
				continue
			}
			name := normalizePythonName(parts[0])
			constraint := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
			result = append(result, model.Dependency{Name: name, Version: constraint, Constraint: constraint,
				Ecosystem: "PyPI", Direct: true, SourceType: classifySource(constraint), Manifest: filepath.Base(path), Line: line})
		}
	}
	return result, scanner.Err()
}

func parsePoetryLock(path string) ([]model.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var result []model.Dependency
	var name, version string
	flush := func() {
		if name != "" && version != "" {
			result = append(result, model.Dependency{Name: normalizePythonName(name), Version: version,
				Ecosystem: "PyPI", SourceType: model.SourceRegistry, Manifest: filepath.Base(path)})
		}
		name, version = "", ""
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text == "[[package]]" {
			flush()
			continue
		}
		parts := strings.SplitN(text, "=", 2)
		if len(parts) != 2 {
			continue
		}
		value := strings.Trim(strings.TrimSpace(parts[1]), "\"")
		switch strings.TrimSpace(parts[0]) {
		case "name":
			name = value
		case "version":
			version = value
		}
	}
	flush()
	return result, scanner.Err()
}
