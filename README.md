<div align="center">

# RepoDoctor

**A fast repository health and software supply-chain scanner for developers.**

[![CI](https://github.com/DevPooks/repodoctor/actions/workflows/ci.yml/badge.svg)](https://github.com/DevPooks/repodoctor/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](go.mod)
[![License: MIT](https://img.shields.io/badge/License-MIT-2ea44f.svg)](LICENSE)

[English](README.md) · [Español](README.es.md)

</div>

RepoDoctor inspects a local repository without installing its dependencies or running project code. It combines advisory lookups with static checks for dependency provenance, suspicious package names, install scripts, likely secrets, missing project files, CI/tests, large source files, and unresolved work markers—then produces one report that works for a terminal or CI job.

```text
$ repodoctor scan .

RepoDoctor
Scanning: /work/example

Supply Chain & Security
───────────────────────────────
✗ KNOWN_VULNERABILITY [RD-SEC-001] — package-lock.json example@1.0.0
  An exact resolved version matches a public advisory.
  Fix: Review the advisory and upgrade to a fixed version.

⚠ POSSIBLE_TYPOSQUAT [RD-SEC-004] — package.json lodahs@1.0.0
  Package name is very similar to the common package lodash.
  Fix: Confirm the package name, publisher, provenance, and registry page.

Summary
Critical: 0
High:     1
Medium:   1
Low:      0
Exit code: 2
```

## Why RepoDoctor?

Modern repositories often trust hundreds of third-party packages before their own code starts. A vulnerable version, compromised release, misspelled name, or unexpected install script can cross that trust boundary during a routine install. Package suggestions copied from setup guides or coding assistants add another failure mode: a plausible name may be wrong or may not exist at all.

RepoDoctor provides a first-pass review before that trust is granted. It does not claim to prove a package safe. It makes concrete evidence—lockfile versions, OSV records, registry existence, source URLs, scripts, and repository state—easy to inspect.

## Checks that are implemented

### Dependencies and supply chain

- Extracts npm packages from `package.json`, `package-lock.json`, and `npm-shrinkwrap.json`.
- Extracts Python packages from `requirements.txt`, `pyproject.toml`, and `poetry.lock`.
- Extracts Go modules from `go.mod` when present.
- Prefers exact lockfile versions and preserves whether a dependency is direct.
- Queries the OSV batch API for exact versions and recognizes OpenSSF malicious-package records (`MAL-*`).
- Checks direct npm/PyPI packages for registry existence and package age.
- Flags possible typosquats with edit distance against a small set of common package names.
- Flags Git, GitHub, local-path, and arbitrary HTTP sources for review.
- Flags mutable ranges when no exact lockfile resolution is available.
- Statically inspects `preinstall`, `install`, `postinstall`, and `prepare` scripts for risky command combinations.

### Repository health and quality

- Checks README, license, `.gitignore`, `SECURITY.md`, CI, and likely tests.
- Uses `git ls-files` when available to catch tracked `.env`, dependency directories, virtual environments, and build output.
- Detects high-confidence secret patterns and prints only a redacted preview.
- Reports oversized source files while skipping common generated/lock files.
- Reports `TODO`/`FIXME` comments with file and line number.

## Safety model

RepoDoctor is deliberately static. It never:

- installs a package;
- imports code from the scanned repository;
- runs lifecycle scripts;
- executes repository binaries;
- attempts to exploit a vulnerability;
- dynamically analyzes suspected malware;
- modifies the scanned repository by default.

Only package coordinates needed for OSV and registry metadata checks leave the machine. File contents and detected secret values stay local.

## Installation

Build from source with Go 1.23 or newer:

```bash
git clone https://github.com/DevPooks/repodoctor.git
cd repodoctor
make build
./bin/repodoctor version
```

After tagged releases are available, `go install` is also supported:

```bash
go install github.com/DevPooks/repodoctor/cmd/repodoctor@latest
```

## Quick start

```bash
repodoctor scan .
repodoctor scan . --format json
repodoctor scan . --ci
repodoctor deps .
repodoctor security .
repodoctor health .
repodoctor explain RD-SEC-004
```

Use `--offline` when a deterministic local-only scan is more important than advisory freshness:

```bash
repodoctor scan . --offline --format json --output repodoctor-report.json
```

## Commands

| Command | Scope |
|---|---|
| `scan` | Dependencies, security, health, and quality |
| `deps` | Manifest/lockfile extraction and source/pinning checks |
| `security` | Dependency, OSV, registry, secret, and lifecycle checks |
| `health` | Repository files, Git hygiene, tests, CI, and quality |
| `explain` | Stable rule explanation and recommended action |
| `version` | Build version |

Flags may appear before or after the path. External work is bounded by `--timeout` (45 seconds by default), OSV calls retry transient failures, and registry requests use a five-worker pool rather than one goroutine per package.

## Configuration

Create `.repodoctor.yml` in the scanned repository:

```yaml
ignore:
  packages:
    - example-safe-internal-package
  paths:
    - testdata

rules:
  large_file_lines: 500
  package_age_warning_days: 14

security:
  osv: true
  registry_metadata: true
  secret_scan: true

severity_overrides:
  RD-HEALTH-003: low

ignore_findings:
  - RD-SEC-006:example-package
```

Suppression is explicit: the report includes `suppressed_finding_count`. A package ignore also prevents that package's coordinates from being sent to external metadata services.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | No blocking findings |
| `1` | Medium/low warnings found |
| `2` | High or critical finding found |
| `3` | Scan/configuration/output failure |

Informational findings alone do not fail a build.

## CI usage

```yaml
name: Repository health
on: [push, pull_request]

jobs:
  repodoctor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.23.x"
      - run: go run github.com/DevPooks/repodoctor/cmd/repodoctor@latest scan . --ci
```

For reproducible CI, pin a release tag instead of `@latest`. JSON uses schema version `1.0` and includes lookup status, counts, findings, dependencies, duration, and suppression count.

## How detection works

RepoDoctor separates evidence from heuristics:

- **Known vulnerability:** exact package/version evidence returned by OSV.
- **Known malicious package:** an authoritative malicious-package record returned through OSV/OpenSSF.
- **Possible typosquat/authenticity review:** registry absence, very recent registration, or a close name. This never becomes a malware verdict on its own.
- **Suspicious install script:** an install lifecycle phase plus static shell/network indicators. A normal build script is not flagged merely for existing.
- **Likely secret:** a high-confidence local pattern. The report stores location, type, and redacted preview—not the full value.

The complete stable catalog is in [finding codes](docs/finding-codes.md).

## Data sources and network behavior

- [OSV](https://osv.dev/) supplies open vulnerability records through `/v1/querybatch`.
- [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) publishes malicious-package reports in the OSV format.
- npm and PyPI metadata endpoints provide package existence and release timestamps.

An unavailable advisory service produces `vulnerability_lookup: "unavailable"`. It never produces the misleading statement “no vulnerabilities found.” Registry and advisory failures do not erase the local static findings.

## Threat model and false positives

RepoDoctor helps with known advisories, known malicious releases, dependency confusion signals, install-time behavior, accidental credential commits, and missing repository controls. It cannot certify that a package is benign, inspect behavior hidden inside an archive it never downloads, or detect a vulnerability that has not been published.

Name similarity and package age are review prompts. Internal packages, forks, and new legitimate releases can trigger them. Use scoped suppressions only after confirming provenance, and keep the reason in version control. See the full [threat model](docs/threat-model.md).

## Privacy

Repository contents are not uploaded. OSV receives package name, ecosystem, and exact version. npm/PyPI receive direct package names through ordinary metadata requests. `--offline` disables both kinds of request.

## Current limitations

- npm and Python parsing covers common manifest/lockfile shapes, not every package-manager extension.
- Go module extraction is supported, but registry metadata checks currently target npm and PyPI.
- CVSS vector strings without a numeric score use a conservative high-severity default unless OSV provides a severity label.
- There is no local advisory cache yet.
- Secret detection favors precision over exhaustive entropy scanning.
- Registry popularity is represented by a small review list, not download-count scoring.

## Roadmap

- Advisory and registry cache with TTL and `cache clear`.
- Richer PEP 508 and Poetry source parsing.
- Signed release binaries and SBOM/provenance metadata.
- Optional SARIF output for code-scanning interfaces.
- Ecosystem-specific policy packs without turning the scanner into a package manager.

## Development

```bash
make check       # formatting, vet, tests, build
make test-race   # race detector
make scan        # scan RepoDoctor itself without network calls
```

External APIs are mocked with `httptest`; the automated suite does not depend on live OSV, npm, or PyPI availability. Synthetic fixtures contain no executable malware.

## License

MIT © 2026 DevPooks
