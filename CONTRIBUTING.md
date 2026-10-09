# Contributing

Changes should preserve the central safety property: scanning a repository must not execute or install its contents.

```bash
make check
make test-race
make scan
```

When adding a rule:

- assign and document a stable finding code;
- separate authoritative evidence from heuristics;
- include a concrete recommendation and confidence level;
- test success, malformed input, and unavailable external service behavior;
- use synthetic, non-functional fixtures;
- update both README languages when CLI behavior changes.

Do not add a large embedded malware list. Prefer authoritative metadata with explicit freshness and failure semantics.
