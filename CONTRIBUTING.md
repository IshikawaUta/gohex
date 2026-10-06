# Contributing to GoHex

Thanks for helping. This project is a lawful, defensive forensic tool; please read
this together with [SECURITY.md](SECURITY.md) and [docs/legal.md](docs/legal.md).

## Ground rules

- **No harmful features.** Contributions implementing any item in the *Non-goals*
  list (wiping, bypass, anti-forensics, credential extraction, live process
  editing, stealth) will be rejected.
- **Read-only by default.** Any new write path must go through the write-guard
  (`--allow-unsafe-write` + two-step confirmation + audit log).
- **No telemetry or outbound network** without explicit opt-in.

## Developer certificate of origin (DCO)

Every commit must be signed off:

```
git commit -s -m "feat(hex): add wildcard search"
```

Which adds: `Signed-off-by: Your Name <you@example.com>` — certifying you have the
right to submit the work under the Apache-2.0 license (see
[DCO v1.1](https://developercertificate.org/)).

## Workflow

1. Fork and create a feature branch from `main`.
2. Keep modules decoupled: parser/engine packages must stay free of GUI imports.
3. Tests are mandatory; core packages target ≥ 80% statement coverage.
4. Fuzz seeds belong in `test/fuzz/` for any new parser code.
5. Run before pushing:

```bash
go test ./...
go test -coverprofile=coverage.out ./internal/... && go tool cover -func=coverage.out
go vet ./...
gofumpt -l .          # go install mvdan.cc/gofumpt@latest
golangci-lint run      # optional, used in CI
```

6. Open a PR with: what/why, test plan, screenshots for UI changes, and a
   `Signed-off-by` trailer.

## Commit style

Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`) — the
CHANGELOG is generated from them (git-cliff in release CI).

## Questions

Open a discussion issue for architecture changes before investing in a large PR.
