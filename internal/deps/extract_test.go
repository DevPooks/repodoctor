package deps

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractPrefersResolvedLockfileVersion(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", `{"dependencies":{"express":"^4.18.0"}}`)
	write(t, root, "package-lock.json", `{"packages":{"":{"dependencies":{"express":"^4.18.0"}},"node_modules/express":{"version":"4.18.3","resolved":"https://registry.npmjs.org/express/-/express-4.18.3.tgz"}}}`)

	dependencies, err := Extract(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(dependencies) != 1 || dependencies[0].Version != "4.18.3" || !dependencies[0].Direct {
		t.Fatalf("unexpected dependencies: %#v", dependencies)
	}
	if dependencies[0].Constraint != "^4.18.0" {
		t.Fatalf("expected manifest constraint to be preserved, got %q", dependencies[0].Constraint)
	}
}

func TestExtractRequirementsAndDirectURL(t *testing.T) {
	root := t.TempDir()
	write(t, root, "requirements.txt", "requests==2.32.3\nprivate-lib @ https://packages.example.test/private-lib.tgz\n")
	dependencies, err := Extract(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(dependencies) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(dependencies))
	}
	if dependencies[1].Name != "requests" || dependencies[1].Version != "2.32.3" {
		t.Fatalf("exact requirement not parsed: %#v", dependencies[1])
	}
}

func write(t *testing.T, root, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
