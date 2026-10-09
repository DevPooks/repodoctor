package model

type Rule struct {
	Code        string
	Name        string
	Explanation string
	Action      string
}

var Rules = map[string]Rule{
	"RD-SEC-001":     {"RD-SEC-001", "KNOWN_VULNERABILITY", "An exact resolved package version matches a public OSV advisory.", "Review the advisory and upgrade to a fixed version."},
	"RD-SEC-002":     {"RD-SEC-002", "KNOWN_MALICIOUS_PACKAGE", "OSV/OpenSSF identifies the package version as malicious.", "Remove the package, rotate exposed credentials, and investigate affected builds."},
	"RD-SEC-003":     {"RD-SEC-003", "SUSPICIOUS_INSTALL_SCRIPT", "An npm lifecycle script combines install-time execution with a risky shell or network command.", "Read the script and referenced files before installing dependencies."},
	"RD-SEC-004":     {"RD-SEC-004", "POSSIBLE_TYPOSQUAT", "A dependency name resembles a common package or could not be verified in its registry. This is a heuristic, not a malware verdict.", "Confirm the package name, publisher, provenance, and intended registry page."},
	"RD-SEC-005":     {"RD-SEC-005", "DIRECT_URL_DEPENDENCY", "A dependency is fetched from a URL, Git reference, or external path instead of a normal registry release.", "Prefer a reviewed immutable release; otherwise pin a commit and verify the source."},
	"RD-SEC-006":     {"RD-SEC-006", "UNPINNED_DEPENDENCY", "Only a mutable range or branch is available for this dependency.", "Commit a lockfile or pin an immutable version."},
	"RD-SEC-007":     {"RD-SEC-007", "POSSIBLE_SECRET", "A tracked text file contains a high-confidence secret pattern. The reported preview is redacted.", "Revoke the credential, remove it from history, and load replacements from a secret store."},
	"RD-HEALTH-001":  {"RD-HEALTH-001", "MISSING_README", "The repository has no obvious README file.", "Add a README with purpose, setup, usage, and limitations."},
	"RD-HEALTH-002":  {"RD-HEALTH-002", "MISSING_LICENSE", "The repository does not declare a license.", "Choose and add a license that matches the intended use."},
	"RD-HEALTH-003":  {"RD-HEALTH-003", "MISSING_CI", "No common continuous-integration configuration was found.", "Add a minimal pipeline for tests, linting, and builds."},
	"RD-HEALTH-004":  {"RD-HEALTH-004", "MISSING_TESTS", "No obvious test file or test configuration was found.", "Add focused tests for core behavior and failure paths."},
	"RD-HEALTH-005":  {"RD-HEALTH-005", "MISSING_GITIGNORE", "The repository has no .gitignore file.", "Ignore local credentials, dependencies, build output, and editor state."},
	"RD-HEALTH-006":  {"RD-HEALTH-006", "MISSING_SECURITY_POLICY", "The repository has no SECURITY.md file.", "Document supported versions and a private reporting path."},
	"RD-HEALTH-007":  {"RD-HEALTH-007", "TRACKED_BUILD_ARTIFACT", "A dependency directory, virtual environment, or build artifact appears tracked by Git.", "Remove generated artifacts from Git and add an ignore rule."},
	"RD-SEC-008":     {"RD-SEC-008", "TRACKED_ENV_FILE", "An environment file appears tracked by Git.", "Remove it from Git, rotate any credentials, and commit a redacted .env.example instead."},
	"RD-QUALITY-001": {"RD-QUALITY-001", "LARGE_SOURCE_FILE", "A source file exceeds the configured line threshold.", "Review whether responsibilities can be split without creating artificial layers."},
	"RD-QUALITY-002": {"RD-QUALITY-002", "TODO_FOUND", "A TODO or FIXME marker remains in source.", "Resolve it or link it to a tracked issue with enough context."},
}
