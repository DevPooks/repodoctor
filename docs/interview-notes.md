# Interview notes

## Short explanation

RepoDoctor is a Go CLI that statically inspects a repository before dependencies are installed. It extracts exact package versions where possible, queries OSV/OpenSSF records, checks npm/PyPI metadata, and combines that with local rules for dependency sources, install scripts, secrets, Git hygiene, tests, CI, and maintainability. It has stable JSON and exit codes so the same engine works locally and in CI.

## Software supply-chain security

The software supply chain includes the packages, registries, build scripts, tools, and metadata used to produce an application. Trusting a dependency means trusting more than its API: maintainers, publishing accounts, release artifacts, transitive dependencies, and install-time behavior all matter.

## Vulnerability versus malware

A vulnerability is a defect that can be exploited under some conditions. Malware is intentionally harmful behavior. A legitimate package version can be vulnerable; a malicious package may not need a software bug at all. RepoDoctor uses separate codes and does not turn a visual/name heuristic into a malware claim.

## OSV and OpenSSF Malicious Packages

OSV is an open schema and API for vulnerability data keyed by ecosystem, package, and version. The batch endpoint reduces request overhead. OpenSSF Malicious Packages publishes reports for malicious releases using the OSV format, which lets the same transport return `MAL-*` records.

## Typosquatting and slopsquatting

Typosquatting registers a name close to a trusted package, such as a transposed character. Slopsquatting describes risk around nonexistent package names suggested by generated instructions or coding tools: someone may later register the invented name. Registry absence and edit distance are review signals, not proof of intent.

## Why static scanning is safer

Installing a suspect package would run the exact trust boundary the tool is meant to inspect. Static scanning reads manifests, lockfiles, scripts, and repository text without importing code or executing lifecycle hooks. The tradeoff is visibility: hidden archive contents and unpublished threats remain out of scope.

## False positives

Internal packages may be absent from public registries; new packages can be legitimate; direct Git references can be intentional. Findings include confidence, evidence, and a recommendation. Configuration supports a scoped package or finding key, and suppression count remains visible.

## Why lockfiles matter

A range such as `^4.18.0` does not identify what was actually installed. An exact lockfile version enables deterministic advisory lookup and repeatable builds. RepoDoctor prefers lock data while preserving that the package was directly declared.

## CI exit codes

Zero means no blocking findings, one means medium/low warnings, two means high/critical evidence, and three means the scan itself failed. Informational TODO comments do not fail a build. Teams can override severity or suppress a reviewed key in version-controlled config.

## Go concurrency

The OSV client batches requests. npm/PyPI lookups go through a fixed five-worker pool, which improves latency without creating unbounded goroutines. A context deadline propagates cancellation through HTTP requests. Results are sorted after collection so output stays deterministic.

## Mocking HTTP

The OSV client depends on a small `Doer` interface. Registry base URLs and the HTTP client are configurable. Tests use `httptest.Server` for success, malicious-record, 404, and timeout behavior; they never depend on public services.

## Tradeoffs to discuss

- A small explainable popular-package list is easier to defend than an opaque popularity score, but has less coverage.
- Conservative secret patterns reduce noise but miss unknown formats.
- No cache keeps freshness/failure semantics simple; a TTL cache is the next latency/offline improvement.
- JSON schema versioning acknowledges that machine consumers need compatibility, even while the CLI is young.
