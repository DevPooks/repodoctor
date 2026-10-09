# Finding code catalog

Codes are stable identifiers intended for CI policy, suppressions, and machine consumers. Titles may become clearer over time; a code's core meaning will not be silently repurposed.

| Code | Name | Default severity | Evidence |
|---|---|---:|---|
| `RD-SEC-001` | `KNOWN_VULNERABILITY` | high* | Exact package/version returned by OSV |
| `RD-SEC-002` | `KNOWN_MALICIOUS_PACKAGE` | critical | `MAL-*` OSV/OpenSSF record |
| `RD-SEC-003` | `SUSPICIOUS_INSTALL_SCRIPT` | medium/high | Install lifecycle phase plus risky static command signals |
| `RD-SEC-004` | `POSSIBLE_TYPOSQUAT` | low/medium | Registry absence/age and explainable name similarity |
| `RD-SEC-005` | `DIRECT_URL_DEPENDENCY` | medium/high | Non-registry dependency source |
| `RD-SEC-006` | `UNPINNED_DEPENDENCY` | medium | Direct registry dependency without exact resolution |
| `RD-SEC-007` | `POSSIBLE_SECRET` | high | High-confidence local pattern; output redacted |
| `RD-SEC-008` | `TRACKED_ENV_FILE` | high | `.env`-style file returned by `git ls-files` |
| `RD-HEALTH-001` | `MISSING_README` | medium | Root file check |
| `RD-HEALTH-002` | `MISSING_LICENSE` | low | Root file check |
| `RD-HEALTH-003` | `MISSING_CI` | medium | Common CI configuration check |
| `RD-HEALTH-004` | `MISSING_TESTS` | medium | Test filename/config heuristic |
| `RD-HEALTH-005` | `MISSING_GITIGNORE` | low | Root file check |
| `RD-HEALTH-006` | `MISSING_SECURITY_POLICY` | low | Root file check |
| `RD-HEALTH-007` | `TRACKED_BUILD_ARTIFACT` | medium | Generated/dependency path returned by Git |
| `RD-QUALITY-001` | `LARGE_SOURCE_FILE` | low | Configured line threshold |
| `RD-QUALITY-002` | `TODO_FOUND` | info | TODO/FIXME comment marker |

`*` OSV-provided severity can lower or raise `RD-SEC-001`. A configured `severity_overrides` entry is applied after detection.

## Suppression keys

The most specific key is preferred:

```yaml
ignore_findings:
  - RD-SEC-006:example-package
  - RD-QUALITY-001:internal/generated_fixture.go
```

A code by itself suppresses every finding from that rule. Every suppression increments the report's visible suppression count.
