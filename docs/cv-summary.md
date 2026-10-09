# RepoDoctor — Software Supply-Chain & Repository Health CLI

**Stack:** Go, OSV API, OpenSSF malicious-package data, npm/PyPI metadata, GitHub Actions

## CV bullets

- Built a Go CLI that statically analyzes npm, Python, and Go dependency metadata for known vulnerabilities, authoritative malicious-package records, risky sources/scripts, unpinned versions, and possible typosquatting without executing third-party code.
- Integrated batched OSV lookups, bounded concurrent npm/PyPI metadata checks, conservative local secret detection, configurable repository-health rules, stable JSON output, CI exit codes, and mocked external-service tests.

## LinkedIn project description

RepoDoctor is a safe-by-design repository scanner built in Go. It combines exact lockfile extraction and public advisory data with explainable local heuristics, then returns actionable terminal or JSON reports. The project demonstrates HTTP resilience, context cancellation, bounded concurrency, filesystem/Git inspection, security-oriented error semantics, and testable external-service boundaries.

## ATS keywords

Go, Golang, CLI, software supply chain, OSV, OpenSSF, dependency security, npm, PyPI, static analysis, vulnerability management, typosquatting, secret scanning, JSON, concurrency, context cancellation, GitHub Actions, CI/CD, unit testing, integration testing
