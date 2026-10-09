package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DevPooks/repodoctor/internal/model"
	"github.com/DevPooks/repodoctor/internal/report"
	"github.com/DevPooks/repodoctor/internal/scan"
)

var version = "dev"

type cliOptions struct {
	path    string
	format  string
	ci      bool
	offline bool
	output  string
	timeout time.Duration
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		usage(stdout)
		return 0
	}
	command := args[0]
	if command == "version" {
		fmt.Fprintln(stdout, "RepoDoctor", version)
		return 0
	}
	if command == "explain" {
		if len(args) != 2 {
			fmt.Fprintln(stderr, "usage: repodoctor explain <finding-code>")
			return 3
		}
		rule, ok := model.Rules[strings.ToUpper(args[1])]
		if !ok {
			fmt.Fprintln(stderr, "unknown finding code:", args[1])
			return 3
		}
		fmt.Fprintf(stdout, "%s — %s\n\n%s\n\nRecommended action: %s\n", rule.Code, rule.Name, rule.Explanation, rule.Action)
		return 0
	}
	modeByCommand := map[string]scan.Mode{"scan": scan.ModeAll, "deps": scan.ModeDeps, "security": scan.ModeSecurity, "health": scan.ModeHealth}
	mode, ok := modeByCommand[command]
	if !ok {
		fmt.Fprintln(stderr, "unknown command:", command)
		usage(stderr)
		return 3
	}
	options, err := parseOptions(args[1:])
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 3
	}
	root, err := filepath.Abs(options.path)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 3
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		fmt.Fprintln(stderr, "error: scan target must be an existing directory")
		return 3
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	result, err := scan.Run(ctx, root, scan.Options{Mode: mode, Offline: options.offline})
	if err != nil {
		fmt.Fprintln(stderr, "scan failed:", err)
		return 3
	}
	writer := stdout
	var file *os.File
	if options.output != "" {
		file, err = os.Create(options.output)
		if err != nil {
			fmt.Fprintln(stderr, "write report:", err)
			return 3
		}
		defer file.Close()
		writer = file
	}
	if options.format == "json" {
		err = report.JSON(writer, result)
	} else {
		err = report.Text(writer, result, options.ci)
	}
	if err != nil {
		fmt.Fprintln(stderr, "write report:", err)
		return 3
	}
	return model.ExitCode(result)
}

func parseOptions(args []string) (cliOptions, error) {
	options := cliOptions{path: ".", format: "text", timeout: 45 * time.Second}
	pathSet := false
	for index := 0; index < len(args); index++ {
		argument := args[index]
		value := func(name string) (string, error) {
			if strings.HasPrefix(argument, name+"=") {
				return strings.TrimPrefix(argument, name+"="), nil
			}
			if index+1 >= len(args) {
				return "", fmt.Errorf("%s requires a value", name)
			}
			index++
			return args[index], nil
		}
		switch {
		case argument == "--ci":
			options.ci = true
		case argument == "--offline":
			options.offline = true
		case argument == "--format" || strings.HasPrefix(argument, "--format="):
			var valueErr error
			options.format, valueErr = value("--format")
			if valueErr != nil {
				return options, valueErr
			}
		case argument == "--output" || strings.HasPrefix(argument, "--output="):
			var valueErr error
			options.output, valueErr = value("--output")
			if valueErr != nil {
				return options, valueErr
			}
		case argument == "--timeout" || strings.HasPrefix(argument, "--timeout="):
			raw, valueErr := value("--timeout")
			if valueErr != nil {
				return options, valueErr
			}
			duration, parseErr := time.ParseDuration(raw)
			if parseErr != nil || duration <= 0 {
				return options, errors.New("--timeout must be a positive duration such as 30s")
			}
			options.timeout = duration
		case strings.HasPrefix(argument, "-"):
			return options, fmt.Errorf("unknown option %s", argument)
		default:
			if pathSet {
				return options, errors.New("only one scan path may be provided")
			}
			options.path, pathSet = argument, true
		}
	}
	if options.format != "text" && options.format != "json" {
		return options, errors.New("--format must be text or json")
	}
	return options, nil
}

func usage(writer io.Writer) {
	fmt.Fprintln(writer, `RepoDoctor — static repository health and supply-chain scanner

Usage:
  repodoctor scan [path] [--format text|json] [--ci] [--offline]
  repodoctor deps [path] [--format text|json]
  repodoctor security [path] [--format text|json] [--offline]
  repodoctor health [path] [--format text|json]
  repodoctor explain <finding-code>
  repodoctor version

Options:
  --output <file>     Write the selected report format to a file
  --timeout <value>   Bound external lookups (default 45s)
  --offline           Disable OSV and registry metadata requests`)
}
