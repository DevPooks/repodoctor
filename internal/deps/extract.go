package deps

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/DevPooks/repodoctor/internal/model"
)

func Extract(root string) ([]model.Dependency, error) {
	var all []model.Dependency
	parsers := []struct {
		name string
		fn   func(string) ([]model.Dependency, error)
	}{
		{"package.json", parsePackageJSON},
		{"package-lock.json", parsePackageLock},
		{"npm-shrinkwrap.json", parsePackageLock},
		{"requirements.txt", parseRequirements},
		{"pyproject.toml", parsePyProject},
		{"poetry.lock", parsePoetryLock},
		{"go.mod", parseGoMod},
	}
	for _, parser := range parsers {
		path := filepath.Join(root, parser.name)
		dependencies, err := parser.fn(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", parser.name, err)
		}
		all = append(all, dependencies...)
	}

	// Lockfile entries replace range-only manifest entries while preserving directness.
	deduped := make(map[string]model.Dependency)
	for _, dependency := range all {
		key := dependency.Ecosystem + "\x00" + dependency.Name
		current, exists := deduped[key]
		if !exists || (!current.HasExactVersion() && dependency.HasExactVersion()) {
			dependency.Direct = dependency.Direct || current.Direct
			if dependency.Constraint == "" {
				dependency.Constraint = current.Constraint
			}
			deduped[key] = dependency
			continue
		}
		if dependency.Direct && !current.Direct {
			current.Direct = true
			if current.Constraint == "" {
				current.Constraint = dependency.Constraint
			}
			deduped[key] = current
		}
	}
	result := make([]model.Dependency, 0, len(deduped))
	for _, dependency := range deduped {
		result = append(result, dependency)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Ecosystem == result[j].Ecosystem {
			return result[i].Name < result[j].Name
		}
		return result[i].Ecosystem < result[j].Ecosystem
	})
	return result, nil
}
