# VocSign

VocSign is a cross-platform desktop signer built with Go + Gio.
It imports user certificates, discovers certificates from system/browser stores, and signs signature requests.

## Main capabilities

- Manual certificate import from `.p12` / `.pfx` files.
- Support for password-protected and non-password PKCS#12 files.
- Automatic discovery from NSS/browser stores (Firefox/Chromium/Brave heuristics).
- Import discovered certificates into local encrypted metadata storage.
- UI workflow for opening, reviewing, and signing requests.

## Requirements

- Go `1.25.6` (as declared in `go.mod`).
- `cgo` enabled for full certificate discovery support.
- Optional Docker for reproducible cross-builds.

Platform-specific compilers (only needed for local cross-compilation):
- Windows: `x86_64-w64-mingw32-gcc`
- macOS: `o64-clang`, `oa64-clang` (osxcross toolchain)

## Run locally

```bash
go run ./cmd/vocsign
```

## Build

From `vocsign/`:

```bash
make all
```

Useful targets:

```bash
make build-host
make build-linux-amd64
make build-windows-amd64
make build-darwin-amd64
make build-darwin-arm64
make release-local
make release-docker-core
make release-docker-macos
make release-docker
```

## Tests

```bash
make test
```

## Certificate discovery behavior

Automatic scan currently combines:

- NSS-based stores (Firefox profiles + browser profile heuristics).
- Browser profile selection heuristics from `profiles.ini` / active-profile signals.
- Environment overrides for NSS library resolution:
  - `VOCSIGN_NSS_LIB`
  - `NSS_LIB_PATH`

Notes:

- Windows browser discovery depends on NSS + `cgo` support in the built binary.
- Native OS-store listing is currently implemented on macOS only in this repository.

## Local storage model

Imported identities are stored in a local file store:

- Metadata: JSON (certificate, fingerprint, source reference)
- Private key material (manual `.p12/.pfx` import): encrypted at rest
- System/browser imported identities: stored as references (PKCS#11 or OS-native ref)

## Project layout

- `cmd/vocsign`: desktop app entrypoint.
- `internal/ui`: screens, widgets, theme.
- `internal/app`: app state and workflow orchestration.
- `internal/crypto/pkcs12store`: PKCS#12 parsing, local store, signer resolution.
- `internal/crypto/systemstore`: NSS/system discovery.
- `internal/crypto/cades`: CAdES signing.
- `internal/net`: request fetch/submit.
- `test`: integration/unit/legal tests and test certificates.

## Troubleshooting

- `make all` fails with permissions in `build/`:
  - The Makefile now auto-renames non-writable `build/` to `build.stale.<timestamp>`.
- Windows scan finds no browser certificates:
  - Ensure Firefox/NSS DB exists for the user profile.
  - Ensure binary was built with `CGO_WINDOWS=1`.
  - Optionally set `VOCSIGN_NSS_LIB` to `softokn3.dll`/`nss3.dll` path.

## License

See `LICENSE`.
