package rules

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var ignoredDirectories = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true, "venv": true,
	"dist": true, "build": true, "target": true, "coverage": true, ".next": true,
}

func walkTextFiles(root string, ignoredPaths []string, visit func(path, relative string, data []byte) error) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path != root && (ignoredDirectories[entry.Name()] || pathIgnored(relative, ignoredPaths)) {
				return filepath.SkipDir
			}
			return nil
		}
		if pathIgnored(relative, ignoredPaths) || entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := entry.Info()
		if err != nil || info.Size() > 2*1024*1024 {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.IndexByte(data, 0) >= 0 {
			return nil
		}
		return visit(path, filepath.ToSlash(relative), data)
	})
}

func pathIgnored(relative string, patterns []string) bool {
	relative = filepath.ToSlash(relative)
	for _, pattern := range patterns {
		pattern = filepath.ToSlash(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		if matched, _ := filepath.Match(pattern, relative); matched || relative == pattern || strings.HasPrefix(relative, strings.TrimSuffix(pattern, "/")+"/") {
			return true
		}
	}
	return false
}

func trackedFiles(root string) ([]string, bool) {
	command := exec.Command("git", "-C", root, "ls-files", "-z")
	output, err := command.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return nil, false
		}
		return nil, false
	}
	parts := bytes.Split(output, []byte{0})
	files := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) > 0 {
			files = append(files, filepath.ToSlash(string(part)))
		}
	}
	return files, true
}
