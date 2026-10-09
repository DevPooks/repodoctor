package deps

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/DevPooks/repodoctor/internal/model"
)

func parseGoMod(path string) ([]model.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var result []model.Dependency
	inBlock := false
	scanner := bufio.NewScanner(file)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(strings.SplitN(scanner.Text(), "//", 2)[0])
		switch text {
		case "require (":
			inBlock = true
			continue
		case ")":
			inBlock = false
			continue
		}
		if strings.HasPrefix(text, "require ") {
			text = strings.TrimSpace(strings.TrimPrefix(text, "require "))
		} else if !inBlock {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) < 2 {
			continue
		}
		result = append(result, model.Dependency{Name: fields[0], Version: fields[1],
			Ecosystem: "Go", Direct: true, SourceType: model.SourceRegistry, Manifest: filepath.Base(path), Line: line})
	}
	return result, scanner.Err()
}
