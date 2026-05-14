# VocSign

VocSign is a system for collecting legally-binding electronic signatures on citizen proposals (Iniciativa Legislativa Popular — ILP) under Catalonia ILP law.
Similar regions in Spain may have similar laws and given the supported certificates it probably allows to collect legally-binding electronic signatures for other citizen proposals in other regions. This last part remains untested.

It has two components:

1. **Desktop client** (Go + [Gio](https://gioui.org)) — imports user certificates, verifies signing requests, produces CAdES detached signatures, and submits them.
2. **Web portal** (Node.js + React) — lets organizers create proposals, generates cryptographically signed manifests, collects and verifies signatures, and tracks progress.

```
┌─────────────────────────────────────────────────────────────────┐
│                        Web Portal                               │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │ React SPA    │───▶│ Express API  │───▶│ MongoDB (rs0)    │   │
│  │ (Vite)       │    │ :8080        │    │ :27017           │   │
│  └──────────────┘    └──────┬───────┘    └──────────────────┘   │
│                             │ /jwks.json                        │
│                             │ /request/:id                      │
│                             │ /api/callback/:id                 │
└─────────────────────────────┼───────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          │   Desktop Client  │                   │
          │   ┌───────────────▼────────────────┐  │
          │   │ 1. Fetch manifest              │  │
          │   │ 2. Verify JWS (organizer sig)  │  │
          │   │ 3. Fetch & hash-check document │  │
          │   │ 4. Generate ILP XML            │  │
          │   │ 5. Sign XML with CAdES         │  │
          │   │ 6. POST to callback            │  │
          │   └────────────────────────────────┘  │
          │                                       │
          │   Certificate sources:                │
          │   • PKCS#12 files (.p12/.pfx)         │
          │   • PKCS#11 hardware tokens           │
          │   • NSS browser stores                │
          │   • macOS Keychain                    │
          └───────────────────────────────────────┘
```

---

## Table of contents

- [End-to-end signing flow](#end-to-end-signing-flow)
- [Project structure](#project-structure)
- [Desktop client](#desktop-client)
  - [Cryptographic subsystem](#cryptographic-subsystem)
  - [Certificate discovery](#certificate-discovery)
  - [Data models](#data-models)
  - [UI screens](#ui-screens)
- [Web portal](#web-portal)
  - [API endpoints](#api-endpoints)
  - [Server-side signature verification](#server-side-signature-verification)
  - [Frontend pages](#frontend-pages)
  - [MongoDB schemas](#mongodb-schemas)
- [Supported certificates](#supported-certificates)
- [Configuration](#configuration)
- [Run locally](#run-locally)
- [Build](#build)
- [Tests](#tests)
- [License](#license)

---

## End-to-end signing flow

**Organizer creates a proposal:**
1. Organizer POSTs to `/api/proposals` with title, promoter, jurisdiction, summary, legal statement, and a full-text document URL + its SHA-256.
2. The API generates a `requestId`, builds a manifest (the `SignRequest` JSON), signs it with the organizer's ECDSA P-256 private key (JWS compact serialization, ES256), and stores everything in MongoDB.
3. Returns a signing URL that citizens open.

**Citizen signs:**
1. Citizen installs the desktop client and opens the signing URL.
2. The client fetches the manifest from `/request/:requestId`.
3. Validates timestamps, nonce, and the organizer's JWS signature (fetching the public key from `/jwks.json`).
4. Downloads the full-text document and verifies its SHA-256 matches the manifest.
5. The citizen selects a certificate, reviews the proposal, and clicks sign.
6. The client extracts identity data from the certificate (DNI/NIE/CIF, name, birth date) and generates an ILP XML document.
7. Creates a CAdES detached signature over the ILP XML using the citizen's certificate.
8. POSTs the signature, certificate chain, and ILP XML to `/api/callback/:requestId`.
9. The API verifies the CAdES signature cryptographically, checks the signer identity, prevents duplicates, and stores the signature in MongoDB.
10. Returns a receipt. The client writes an audit entry to its local tamper-evident log.

---

## Project structure

```
vocsign/
├── cmd/vocsign/                  # Desktop app entry point (main.go)
├── internal/
│   ├── app/                      # App state, lifecycle, system store scanning
│   ├── canon/                    # Canonical JSON encoding (deterministic field order)
│   ├── crypto/
│   │   ├── cades/                # CAdES detached signature creation (RFC 5652)
│   │   ├── certs/                # Certificate validation + Spanish ID extraction
│   │   ├── jwsverify/            # JWS ES256 verification (organizer signatures)
│   │   ├── pkcs12store/          # PKCS#12 import, AES-256-GCM vault, identity management
│   │   └── systemstore/          # NSS/OS/PKCS#12 certificate discovery
│   ├── model/                    # SignRequest, SignResponse, ILP XML schemas, birth date validation
│   ├── net/                      # HTTP client (fetch manifest, submit signature, check updates)
│   ├── storage/                  # Audit logger with SHA-256 hash chain
│   ├── ui/                       # Gio screens and widgets
│   └── version/                  # Semantic version comparison
├── webapp/
│   ├── apps/
│   │   ├── api/src/              # Express API (TypeScript)
│   │   │   ├── ca-certs/         # Bundled Spanish CA root/intermediate PEMs
│   │   │   ├── ca-trust.ts       # Trust store loader
│   │   │   ├── chain-verify.ts   # Certificate chain verification
│   │   │   ├── revocation.ts     # OCSP + CRL revocation with LTV
│   │   │   └── safe-fetch.ts     # SSRF-safe HTTP client
│   │   └── web/src/              # React frontend (Vite, TypeScript)
│   ├── docker-compose.yml        # MongoDB + webapp services
│   ├── Dockerfile                # Multi-stage Node.js build
│   └── .env.example              # Environment variable template
├── test/                         # Integration tests + cert generation scripts
├── Makefile                      # Cross-platform build targets
├── go.mod                        # Go 1.25, Gio, pkcs7, pkcs11, pkcs12
└── package.json                  # npm workspace root
```

---

## Desktop client

Entry point: `cmd/vocsign/main.go`. Starts a Gio window (1280×920). Also handles a special `--nss-scan-worker` mode used as a subprocess for NSS certificate scanning on platforms that need separate library linking.

### Cryptographic subsystem

Located under `internal/crypto/`. This is the core of the desktop client.

#### CAdES signing (`cades/`)

Produces legally-compliant CMS/PKCS#7 detached signatures per RFC 5652:

- **Content**: Detached (the ILP XML is not embedded in the signature).
- **SigningCertificateV2 attribute**: Binds the signer's certificate to the signature (SHA-256 hash + issuer serial).
- **Authenticated attributes**: messageDigest, signingTime, contentType — integrity-protected.
- **Timestamp** (optional): When `VOCSIGN_TSA_URL` is set, requests an RFC 3161 timestamp token from the TSA, producing a CAdES-T signature.
- **Signature policy** (optional): Embeds a policy OID, hash, and URI when configured.

Supported algorithms:
- RSA (minimum 2048-bit keys; smaller keys rejected)
- ECDSA (P-256 and other standard curves)
- Hash: SHA-256 (required), SHA-384, SHA-512. SHA-1 explicitly rejected.

#### Certificate management (`pkcs12store/`)

Handles the full lifecycle of user certificates:

- **Import**: Parses `.p12`/`.pfx` files. Normalizes legacy BER-encoded files to DER automatically. Extracts the end-entity certificate, private key, and issuer chain.
- **Vault storage**: Certificates are persisted in `~/.vocsign/store/` encrypted with AES-256-GCM (key derived via PBKDF2).
- **Identity struct**: Each imported certificate becomes an `Identity` with: ID, friendly name, `*x509.Certificate`, certificate chain, SHA-256 fingerprint, and a `crypto.Signer` interface for signing.
- **PKCS#11**: Hardware tokens and smart cards are supported via any PKCS#11 library (OpenSC, NSS, Thales). The client enumerates slots, finds signing objects, and uses `C_SignInit`/`C_Sign` for RSA or ECDSA operations.

#### JWS verification (`jwsverify/`)

Verifies that the request manifest was signed by the organizer:

1. Fetches the JWKS from the organizer's URL.
2. Finds the key by KID.
3. Canonicalizes the request JSON (Go struct field order — not alphabetical).
4. Verifies the ES256 (ECDSA P-256) signature.
5. Cross-checks that the JWS payload matches the canonical bytes exactly.

The canonical encoding (`canon/`) is critical: it enforces Go struct declaration order, no HTML escaping, no insignificant whitespace. This guarantees the same byte output from both the TypeScript portal (which signs) and the Go client (which verifies).

#### Certificate validation (`certs/validate.go`)

Pre-signing checks:
- `NotBefore` ≤ now ≤ `NotAfter`
- `digitalSignature` key usage bit present
- RSA key ≥ 2048 bits
- OCSP revocation check (if the certificate has an OCSP responder URL)

#### Identity extraction (`certs/extract.go`)

Parses certificate subject fields to extract:
- **DNI** (8 digits + letter), **NIE** (X/Y/Z + 7 digits + letter), or **CIF** (corporate tax ID)
- Given name, surnames (from X.509 RDN, with English/Catalan fallbacks)
- Birth date (OID `1.3.6.1.5.5.7.9.1` — Subject Directory Attributes)
- Representative certificate detection (via organization ID, CN patterns, issuer markers)

### Certificate discovery

On startup, the desktop client scans for available certificates from multiple sources:

| Source | Mechanism |
|--------|-----------|
| **NSS browser stores** | Firefox, Chromium, Brave, Edge, Opera, Vivaldi, Thunderbird, and `~/.pki/nssdb`. Supports `cert8.db` (legacy) and `cert9.db` (modern). Profile detection from `profiles.ini`. |
| **OS native stores** | macOS Keychain (implemented). Windows CAPI (via CGO). Linux: NSS-only. |
| **PKCS#12 file scanning** | Walks the home directory for `.p12`/`.pfx` files (depth-limited). Auto-imports passwordless files; marks password-protected ones as locked. |
| **PKCS#11 tokens** | Via any PKCS#11 library specified in config. |

Deduplication is by SHA-256 fingerprint. Scanning runs with a 60-second timeout and up to 4 concurrent NSS readers.

### Data models

Defined in `internal/model/`. These are the JSON structures exchanged between the portal and the desktop client.

#### SignRequest (manifest)

The manifest that organizers sign and citizens verify:

```json
{
  "version": "1.0",
  "requestId": "uuid",
  "issuedAt": "2026-01-15T10:00:00Z",
  "expiresAt": "2027-01-15T10:00:00Z",
  "nonce": "base64(16-32 random bytes)",
  "proposal": {
    "title": "...",
    "promoter": "...",
    "jurisdiction": "...",
    "summary": "...",
    "legalStatement": "...",
    "fullText": { "url": "https://...", "sha256": "hex(32 bytes)" }
  },
  "callback": { "url": "https://...", "method": "POST" },
  "organizer": { "kid": "...", "jwkSetUrl": "https://..." },
  "organizerSignature": { "format": "JWS", "value": "header.payload.signature" },
  "policy": { "mode": "...", "oid": "...", "hashAlg": "...", "hash": "...", "uri": "..." }
}
```

Validation rules: nonce must be 16–32 random bytes (replay protection); callback and JWKS URLs must be HTTPS (localhost exempted for dev); `expiresAt` must be in the future and after `issuedAt`.

#### ILP Signer XML

The document that gets CAdES-signed. Structured for Catalan ILP legal compliance:

```xml
<SignaturaILP versio="1.0">
  <ILP>
    <Titol>Proposal Title</Titol>
    <Codi>RequestID</Codi>
  </ILP>
  <Signant>
    <Nom>First Name</Nom>
    <Cognom1>Surname1</Cognom1>
    <Cognom2>Surname2</Cognom2>
    <DataNaixement>YYYY-MM-DD</DataNaixement>
    <TipusIdentificador>DNI|NIE|CIF</TipusIdentificador>
    <NumeroIdentificador>12345678Z</NumeroIdentificador>
  </Signant>
</SignaturaILP>
```

#### SignResponse (callback payload)

What the desktop client POSTs back to the portal:

```json
{
  "version": "1.0",
  "requestId": "...",
  "nonce": "...",
  "signedAt": "2026-01-15T10:05:00Z",
  "payloadCanonicalSha256": "hex(SHA256 of ILP XML)",
  "signatureFormat": "CAdES",
  "signatureDerBase64": "base64(PKCS#7 DER)",
  "signerCertPem": "-----BEGIN CERTIFICATE-----...",
  "chainPem": ["issuer1 PEM", "issuer2 PEM"],
  "signerXmlBase64": "base64(ILP XML)",
  "timestampTokenBase64": "base64(RFC 3161 token)",
  "client": { "app": "vocsign", "version": "...", "os": "linux" }
}
```

### UI screens

Built with Gio (Go-native cross-platform GUI, Material Design):

| Screen | Purpose |
|--------|---------|
| **OpenRequest** | Enter a signing URL or select a local manifest file |
| **RequestDetails** | Display proposal details, verify organizer signature, fetch and hash-check the full-text document |
| **Certificates** | Browse imported and system-discovered certificates, add/remove |
| **Wizard** | Step-by-step signing flow after selecting request + certificate |
| **Audit** | View signed entries from the local audit log with hash chain |
| **About** | Version info, update check, links |

### Audit log

Located in `internal/storage/`. Writes a JSONL file where each entry includes the SHA-256 hash of the previous entry, forming a tamper-evident chain. Fields: timestamp, requestId, signer name/DNI, callback host, certificate fingerprint, status, error, server acknowledgment ID, and `prevHash`.

---

## Web portal

A Node.js monorepo (`webapp/`) with two apps: an Express API and a React frontend.

### API endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/api/health` | — | Health check |
| `GET` | `/jwks.json` | — | Organizer's ECDSA P-256 public key (JWK Set) |
| `GET` | `/api/downloads` | — | Desktop client download URLs per platform |
| `POST` | `/api/proposals` | API key (optional) | Create a proposal. Rate limit: 5/min/IP |
| `GET` | `/api/proposals` | — | List proposals (latest 100, sortable by date or signature count) |
| `GET` | `/api/proposals/:requestId` | — | Single proposal with manifest + signature progress |
| `GET` | `/request/:requestId` | — | Raw manifest JSON (what the desktop client fetches) |
| `POST` | `/api/callback/:requestId` | — | Submit a signature. Rate limit: 30/min/IP |
| `DELETE` | `/api/signatures/:signerId` | API key | GDPR right-to-erasure: delete all signatures for a signer |

### Server-side signature verification

When a signature is submitted to `/api/callback/:requestId`, the API performs:

1. **Schema validation** (Zod): structure, required fields, types.
2. **Request matching**: `requestId` in body matches URL; proposal exists; proposal not expired.
3. **Timestamp check**: `signedAt` within ±5 min of server time (±24 hr tolerance window).
4. **ILP XML parsing**: extracts signer identity from the submitted XML.
5. **CAdES verification**:
   - Parses the PKCS#7 DER signature.
   - Verifies `messageDigest` attribute matches the SHA-256 of the ILP XML.
   - Verifies authenticated attributes integrity (signature over `AuthenticatedAttributes`).
   - Confirms the signer certificate matches the one in the signature.
6. **Certificate validation** (multi-step):
   - **Expiration**: `NotBefore` ≤ now ≤ `NotAfter`.
   - **Key usage**: `digitalSignature` bit must be present.
   - **Issuer allowlist**: issuer CN must match a recognized Spanish CA in `ACCEPTED_ISSUERS`.
   - **Chain verification**: cryptographic verification from signer cert → intermediates → trusted root CA. Bundled roots: FNMT, AOC/CATCert, ACCV, IZENPE, ANF AC (20 certificates). Intermediates must have `CA:true`. Max depth 5.
   - **OCSP revocation check**: contacts the OCSP responder from the certificate's AIA extension. Verifies response signature. Checks freshness (48h).
   - **CRL fallback**: if OCSP fails or returns Unknown, fetches and verifies the CRL from the certificate's CRL Distribution Points.
   - **Long-Term Validation (LTV)**: if a certificate was revoked *after* `signedAt`, the signature is still valid (eIDAS Article 32). Only certificates revoked before signing are rejected.
   - **Hard-fail**: if neither OCSP nor CRL can confirm non-revocation, the signature is rejected.
   - All outbound OCSP/CRL fetches use an SSRF-safe HTTP client (blocks private IPs, enforces size limits and timeouts).
   - Bypass modes:
     - `ALLOW_TEST_CERTS=true` — skip all certificate checks (unit tests).
     - `ALLOW_TEST_CERTS=verify` — run issuer + chain checks against the test CA, skip only revocation (near-production testing).
7. **Identity cross-check**: certificate subject DN must match the identity in the submitted XML.
8. **Duplicate prevention**: one signature per signer (identified by DNI/NIE/CIF) per proposal.
9. **Storage**: saves via MongoDB transaction, increments the proposal's signature counter.

### Frontend pages

React + Vite + TypeScript SPA:

| Page | Route | Purpose |
|------|-------|---------|
| **Dashboard** | `/` | List all proposals, sort by recent or signature count, create button |
| **Create Proposal** | `/create` | Form: title, promoter, jurisdiction, summary, legal statement, full-text URL + SHA-256 |
| **Proposal** | `/proposal/:id` | Proposal details, signing URL, progress bar towards target |
| **How to Sign** | `/how-to-sign` | Instructions for downloading and using the desktop client |

### MongoDB schemas

**Proposal:**
- `requestId` (unique), `targetSignatures`, `signaturesCount`, `manifest` (full SignRequest JSON), timestamps.

**Signature:**
- `requestId`, `signerId` (unique per proposal — the DNI/NIE/CIF), `signerName`, certificates, timestamps, client metadata.

---

## Supported certificates

### Formats

| Format | Details |
|--------|---------|
| **PKCS#12** (`.p12` / `.pfx`) | Password-protected and password-less. Legacy BER-encoded files normalized automatically. |
| **PKCS#11** (hardware tokens / smart cards) | RSA and ECDSA signing via any PKCS#11 library (e.g. OpenSC, NSS). |
| **NSS system stores** | Auto-discovery from Firefox, Chromium-family browsers, Thunderbird, and `~/.pki/nssdb`. Both `cert8.db` and `cert9.db`. |

### Recognized Spanish / EU certificate authorities

Root and intermediate certificates are bundled in `webapp/apps/api/src/ca-certs/` for cryptographic chain verification. The server validates that every signer certificate chains to one of these trusted roots.

| Authority | Bundled certs | Notes |
|-----------|--------------|-------|
| **FNMT** (Fábrica Nacional de Moneda y Timbre) | 2 (root + intermediate) | AC Raiz FNMT-RCM, AC FNMT Usuarios |
| **Consorci AOC** (Catalonia) | 6 (legacy + G3 hierarchy) | EC-ACC root, EC-Ciutadania, EC-SectorPublic, plus new ECDSA G3 certs |
| **ACCV** (Comunitat Valenciana) | 4 (legacy + eIDAS 2023) | ACCVRAIZ1, ACCVCA-120, plus new RSA eIDAS roots |
| **IZENPE** (Basque Country) | 5 (QC 2020 + legacy 2007) | ROOT CA QC IZENPE, citizen intermediates |
| **ANF AC** | 3 (roots + eSignature intermediate) | ANF Global Root CA, ANF Secure Server Root CA |

In addition to chain verification, the server performs OCSP/CRL revocation checking with Long-Term Validation (LTV) and hard-fail policy.

Set `ALLOW_TEST_CERTS` on the API to control certificate validation during development:

- `true` — bypass all checks (issuer, chain, revocation). Use for unit tests with arbitrary certs.
- `verify` — load the test CA (`test/certs/ec-ciutadania-test-ca.pem`) into the trust store, run issuer allowlist and chain verification, skip only revocation. Use with `test/certs/idcat_full_nopass.p12` to exercise the near-production signing flow.

### Identity extraction

Certificates from the above CAs are parsed to extract:
- **DNI** (8 digits + letter), **NIE** (X/Y/Z + 7 digits + letter), or **CIF** (corporate tax ID)
- Given name, surnames, organization
- Birth date (from Subject Directory Attributes, OID `1.3.6.1.5.5.7.9.1`)

---

## Configuration

### Desktop client environment variables

| Variable | Description |
|----------|-------------|
| `VOCSIGN_TSA_URL` | RFC 3161 Timestamp Authority URL (e.g. `http://timestamp.digicert.com`). Enables CAdES-T signatures. |
| `VOCSIGN_NSS_LIB` | Override path to the NSS library for certificate discovery. |

### Web portal environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Express server port |
| `MONGODB_URI` | — | MongoDB connection string (must be a replica set) |
| `PORTAL_DOMAIN_URL` | — | Public URL of the portal (used in signing URLs) |
| `ORGANIZER_KID` | — | Key ID for JWKS endpoint |
| `ORGANIZER_PRIVATE_KEY_HEX` | — | 64-char hex string: ECDSA P-256 private key scalar |
| `ORGANIZER_JWKS_URL` | — | URL to the JWKS endpoint (usually `{PORTAL_DOMAIN_URL}/jwks.json`) |
| `ORGANIZER_API_KEY` | _(empty = dev mode)_ | Bearer token required for `POST /api/proposals` and `DELETE /api/signatures` |
| `POLICY_OID` | _(optional)_ | Signature policy OID to embed in manifests |
| `POLICY_URI` | _(optional)_ | Signature policy URI |
| `DEFAULT_PROPOSAL_VALIDITY_DAYS` | `365` | How long proposals remain valid |
| `ALLOW_TEST_CERTS` | _(unset)_ | `true` = skip all cert checks; `verify` = issuer + chain only (skip revocation) |
| `VOCSIGN_RELEASE_BASE_URL` | _(optional)_ | GitHub releases URL for desktop download links |

---

## Run locally

### Desktop client

```bash
go run ./cmd/vocsign
```

### Web portal

The portal requires MongoDB with a replica set (needed for transactions).

```bash
# Start MongoDB
cd webapp
docker compose up mongo -d

# Create .env from template
cp .env.example .env
# Edit .env — replace ORGANIZER_PRIVATE_KEY_HEX with:
openssl rand -hex 32

# Install and run
npm install
npm run dev
```

- API: `http://localhost:8080`
- Web (Vite dev server): `http://localhost:5173`

---

## Build

### Requirements

- Go (version in `go.mod`, currently 1.25)
- `cgo` enabled (needed for NSS/system certificate discovery)
- Node.js 22+ and npm (for the web portal)
- Docker (optional, for reproducible cross-builds)

Platform-specific cross-compilers (only for local cross-compilation without Docker):
- Windows: `x86_64-w64-mingw32-gcc`
- macOS: `o64-clang`, `oa64-clang` (osxcross toolchain)

### Make targets

```bash
make build-host              # Build for current platform
make build-linux-amd64       # Linux AMD64
make build-windows-amd64     # Windows AMD64
make build-darwin-amd64      # macOS Intel
make build-darwin-arm64      # macOS Apple Silicon
make release-local           # All four platforms with local toolchains
make release-docker-core     # Linux + Windows in Docker
make release-docker-macos    # macOS in Docker (requires osxcross)
make release-docker          # All platforms via Docker
make test                    # Run all Go tests
make verify                  # Tests + host build
make clean                   # Remove build artifacts
```

Build metadata (version, commit, date) is injected at link time via `-ldflags`.

---

## Tests

### Unit tests (no external dependencies)

```bash
go test ./internal/...
```

Covers:

| Package | What's tested |
|---------|---------------|
| `internal/canon/` | Canonical JSON encoding — field ordering, HTML escaping, determinism |
| `internal/model/` | Request validation (35 cases), ILP XML generation and round-trip |
| `internal/net/` | HTTP redirect checking, response body size limits, document hash verification |
| `internal/version/` | Semantic version comparison |
| `internal/storage/` | Audit logger — JSONL write/read, concurrent access, hash chain tamper detection |
| `internal/crypto/pkcs12store/` | PKCS#12 import, vault encryption (AES-256-GCM round-trip, corruption detection) |
| `internal/crypto/certs/` | Spanish identity extraction (DNI/NIE/CIF, birth date), certificate validation (expiry, key usage, key size) |
| `internal/crypto/cades/` | CAdES timestamp signature value extraction |
| `internal/ui/widgets/` | Autocomplete widget — type-to-filter, accent-insensitive matching, selection state |

### Signing tests (require test certificates)

Generate test certificates if they don't exist, then run:

```bash
cd test && bash gen_certs.sh && cd ..
GENERATE_TEST_CERTS=1 go test ./test/ -run TestGenerateIDCatCertWithAllFields -v  # regenerate IDCat-like certs
go test ./test/ -run 'TestEndToEndWithGeneratedCert|TestLegalComplianceXML'
```

The IDCat cert generator (`TestGenerateIDCatCertWithAllFields`) produces:
- `test/certs/idcat_full_nopass.p12` — user cert matching real EC-Ciutadania DN structure (serialNumber + GN + SN + CN).
- `test/certs/ec-ciutadania-test-ca.pem` — test root CA, auto-loaded into the trust store when `ALLOW_TEST_CERTS` is set.

Covers: PKCS#12 import → CAdES signature creation and verification → ILP XML generation with signer data.

### End-to-end integration test (requires running portal)

Exercises the full flow: create proposal → fetch manifest → sign with CAdES → submit to callback → server-side cryptographic verification.

**Prerequisites:**

```bash
# 1. MongoDB with replica set
cd webapp && docker compose up mongo -d

# 2. API with test certs allowed
cd webapp && npm install && ALLOW_TEST_CERTS=true npx tsx apps/api/src/index.ts

# 3. OpenSSL installed (for dynamic certificate generation)
```

**Run:**

```bash
go test ./test/ -run TestEndToEnd$ -v
```

The test uses an OpenSSL-generated certificate (not from a recognized CA), hence `ALLOW_TEST_CERTS=true`. If the portal is not reachable, the test skips.

### All tests

```bash
go test ./internal/...                    # Unit tests only
go test ./...                             # All including signing + integration
go test -v ./... 2>&1 | cat               # Verbose output
```

---

## License

See `LICENSE`.
