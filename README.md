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

- Go as declared in `go.mod`.
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

## License

See `LICENSE`.
