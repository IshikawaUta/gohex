# GoHex release process

## Versioning

- Semantic Versioning (`vMAJOR.MINOR.PATCH`), starting at `v0.1.0`.
- The version lives in two places and release CI refuses to publish
  unless both equal the tag (without the `v`):
  - `pkg/version.Version` (overridable at build time:
    `-ldflags "-X github.com/IshikawaUta/gohex/pkg/version.Version=v1.2.3"`),
  - `build/config.yml` → `info.version` (packaging metadata).
- `CHANGELOG.md` is maintained by hand from Conventional Commits; the
  GitHub release notes are generated from commit history
  (`gh release create --generate-notes`).

## What a release contains

| Artifact | Platform | Notes |
|---|---|---|
| `gohex-cli-<os>-<arch>[.exe]` | linux, windows, darwin × amd64, arm64 | pure Go, `CGO_ENABLED=0` |
| `gohex`, `.deb`, `.rpm`, `.AppImage` | linux-amd64 | `wails3 task linux:create:{deb,rpm,appimage}` |
| `gohex.exe`, NSIS installer | windows-amd64 | best-effort in CI (MSYS2 + NSIS), WebView2 runtime required |
| `gohex-macos.zip` (`.app`) | darwin-arm64 | best-effort; unsigned — see Signing |
| `SHA256SUMS.txt` (+ `SHA256SUMS.txt.asc`) | all | checksums always; detached GPG signature when configured |

Not automated on purpose: the AUR package needs `makepkg` (Arch-only,
run `wails3 task linux:create:aur` there) and macOS signing/notarization
needs Apple developer credentials (see Signing).

## Release pipeline

`.github/workflows/release.yml` runs on every `v*` tag push:

1. cross-compiles `cmd/gohex-cli` for the 6-target matrix,
2. builds and packages the Linux GUI (deb, rpm, AppImage), the Windows
   NSIS installer and the macOS `.app` (Windows/macOS best-effort — a
   failure there never blocks the release),
3. verifies `pkg/version.Version` and `build/config.yml` `info.version`
   equal the tag,
4. writes `SHA256SUMS.txt` over every artifact and, when the
   `GPG_PRIVATE_KEY` (+ optional `GPG_PASSPHRASE`) repository secrets
   are set, a detached armored signature `SHA256SUMS.txt.asc`,
5. creates the GitHub release with all artifacts and generated notes.

The pre-tag gate stays `.github/workflows/ci.yml` on `main`: tidy/vet/
gofmt, tests + ≥80% coverage, svelte-check + frontend build, bindings
idempotency, 3 OS × 2 arch pure-package cross-compile, GUI build matrix
and the Xvfb smoke launch.

## Local packaging

Packaging is plain `wails3 task` (the Linux three verified locally):

```
wails3 build                               # bin/gohex
wails3 task linux:create:deb               # bin/gohex.deb
wails3 task linux:create:rpm               # bin/gohex.rpm
wails3 task linux:create:appimage          # bin/gohex-x86_64.AppImage
wails3 task windows:package                # NSIS installer (on Windows)
wails3 task darwin:package                 # .app bundle (on macOS)
wails3 task darwin:package:dmg             # styled .dmg (on macOS)
```

## Cross-compilation

- Pure-Go targets (`internal/...`, `pkg/...`, `cmd/gohex-cli`) cross-
  compile anywhere:
  `CGO_ENABLED=0 GOOS=<os> GOARCH=<arch> go build ./cmd/gohex-cli`
  (verified in CI for linux/windows/darwin).
- The GUI needs CGO and the *target* toolchain, so GUI binaries are built
  on their native CI runners (GitHub Actions matrix), not cross-compiled.

## Signing & verification

- **Checksums**: every release carries `SHA256SUMS.txt` covering all
  artifacts.
- **GPG**: when the repository secrets `GPG_PRIVATE_KEY` (armored key)
  and optionally `GPG_PASSPHRASE` are configured, release CI attaches
  `SHA256SUMS.txt.asc`. Consumers verify:

  ```
  gpg --import release-signing-key.asc   # publish the public key once
  gpg --verify SHA256SUMS.txt.asc SHA256SUMS.txt
  sha256sum --check SHA256SUMS.txt
  ```

- **deb/rpm**: `wails3 task linux:sign:packages` signs local packages
  with the key configured via `wails3 setup signing` (system keychain).
  Release CI relies on the checksum signature instead so that package
  repositories can apply their own.
- **macOS**: signing and notarization require an Apple Developer ID
  certificate plus notary credentials; they are deliberately not
  automated. Run `codesign`/`notarytool` manually on `gohex.app` before
  distribution if you have the credentials.

## Release checklist

1. All CI green on `main`.
2. Bump `pkg/version.Version` + `build/config.yml` `info.version` so both
   equal the tag without the `v` (the pipeline refuses otherwise).
3. Update `CHANGELOG.md` with highlights, breaking changes, migration
   notes.
4. Tag `vX.Y.Z` and push; release CI builds the artifacts, checksums and
   the optional signature above.
5. The About panel's update check (no env needed — explicit click) should
   report the new version.
6. Verify on a clean machine: install → first-run disclaimer → open a
   sample → hash matches → save in sandbox mode.

## Hotfix policy

- Security and data-loss fixes may be released as `vX.Y.Z+1` from a hotfix
  branch; everything else waits for the next minor.
- Data-loss bugs are treated as security bugs (see
  [security.md](security.md)).
