# GoHex release process

## Versioning

- Semantic Versioning (`vMAJOR.MINOR.PATCH`), starting at `v0.1.0`.
- The version lives in two places and must match:
  - `pkg/version.Version` (overridable at build time:
    `-ldflags "-X github.com/IshikawaUta/gohex/pkg/version.Version=v1.2.3"`),
  - `build/config.yml` → `info.version` (packaging metadata).
- `CHANGELOG.md` is generated from Conventional Commits with git-cliff in
  release CI (see [CONTRIBUTING.md](../CONTRIBUTING.md)).

## What a release contains

| Artifact | Platform | Notes |
|---|---|---|
| `gohex` | linux-amd64, linux-arm64 | `wails3 build -platform <os/arch>` |
| `gohex.exe` | windows-amd64 | CGO via MinGW-w64, WebView2 runtime required |
| `gohex` | darwin-amd64, darwin-arm64 | CGO via Xcode CLT, signed+notarized (stage 5) |
| `.deb`/`.rpm`, NSIS, AppImage | per platform | `wails3 package` (stage 5 hardening) |

Every release build:

1. runs the full test suite (`go test ./...`, coverage gate ≥80%),
2. runs `npm run check` (svelte-check zero errors) and frontend production
   build,
3. regenerates bindings (`wails3 generate bindings`) and fails CI if the
   frontend no longer compiles against them,
4. builds with `-tags production -trimpath -ldflags "-w -s"` plus the version
   stamp,
5. smoke-launches the binary where a display is available.

## Cross-compilation

- Pure-Go packages (`internal/...`, `pkg/...`) cross-compile anywhere:
  `CGO_ENABLED=0 GOOS=<os> GOARCH=<arch> go build ./internal/... ./pkg/...`
  (verified in CI for linux/windows/darwin).
- The GUI needs CGO and the *target* toolchain, so GUI binaries are built on
  their native CI runners (GitHub Actions matrix), not cross-compiled.

## Release checklist

1. All CI green on `main`.
2. Update `pkg/version.Version` + `build/config.yml` `info.version`.
3. Update `CHANGELOG.md` (git-cliff) with highlights, breaking changes,
   migration notes.
4. Tag `vX.Y.Z` and push; release CI builds artifacts for the matrix above.
5. Attach checksums (SHA-256) to the GitHub release; sign artifacts when the
   signing stage (5) lands. With `GOHEX_UPDATE_CHECK=1`, the About panel's
   update check should then report the new version.
6. Verify on a clean machine: install → first-run disclaimer → open a sample
   → hash matches → save in sandbox mode.

## Hotfix policy

- Security and data-loss fixes may be released as `vX.Y.Z+1` from a hotfix
  branch; everything else waits for the next minor.
- Data-loss bugs are treated as security bugs (see
  [security.md](security.md)).
