package main

import "testing"

func TestOptionsAllowFlagsAfterPath(t *testing.T) {
	options, err := parseOptions([]string{".", "--format", "json", "--ci", "--timeout=5s"})
	if err != nil {
		t.Fatal(err)
	}
	if options.path != "." || options.format != "json" || !options.ci || options.timeout.String() != "5s" {
		t.Fatalf("unexpected options: %#v", options)
	}
}
