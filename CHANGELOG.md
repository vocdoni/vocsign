# Changelog

## Security

---

### SSRF via HTTP redirect following

**Files changed:**
- `internal/net/client.go` (new)
- `internal/net/fetch_request.go`
- `internal/net/submit.go`
- `internal/crypto/jwsverify/jwks.go`

**What was wrong:** All Go HTTP clients (`Fetch`, `Submit`, `FetchJWKS`) used
the default `http.Client`, which silently follows up to 10 HTTP redirects
without restriction. The URL validation in `model.Validate()` only checks that
the *initial* URL uses HTTPS (or localhost), but a malicious server could
respond with a 302 redirect to cloud metadata or internal network. The
redirect would be followed automatically, bypassing the HTTPS requirement.
This is particularly dangerous for the `Submit` function, which sends the
user's digital signature and certificate to whatever URL the redirect points
to.

**What changed:** Created `internal/net/client.go` with a `newClient()`
constructor that attaches a `CheckRedirect` callback. The callback validates
every redirect target against the same rules as `model.Validate()`: the URL
must use HTTPS, or target localhost/127.0.0.1. If a redirect violates this,
the request is aborted with an error. All three HTTP call sites (`Fetch`,
`Submit`, and the JWKS fetcher in `jwsverify`) now use clients with this
redirect checking.

---

### No response body size limits

**Files changed:**
- `internal/net/client.go` (new)
- `internal/net/fetch_request.go`
- `internal/net/submit.go`
- `internal/crypto/jwsverify/jwks.go`

**What was wrong:** `Fetch` used `io.ReadAll(resp.Body)` with no size limit. A
malicious server could send gigabytes of data, causing the desktop application
to run out of memory and crash. The same issue existed in `FetchJWKS` (via
`json.NewDecoder(resp.Body).Decode`) and in the success path of `Submit`.

**What changed:** `client.go` provides a `readAll(r, limit)` helper that wraps
`io.LimitReader` and returns an error if the response exceeds the limit.
`Fetch` and `Submit` now use `readAll(resp.Body, maxResponseBytes)` with a
10 MB cap. `FetchJWKS` uses `io.LimitReader` directly with a 10 MB cap.
These limits are generous enough for any legitimate payload but prevent
memory exhaustion from malicious servers.

---

### No cryptographic verification of submitted signatures

**Files changed:**
- `webapp/apps/api/src/verify-signature.ts` (new)
- `webapp/apps/api/src/index.ts`
- `webapp/apps/api/package.json`

**What was wrong:** The callback endpoint (`POST /api/callback/:requestId`)
stored submitted signatures without verifying them cryptographically. It
validated the JSON schema with Zod and parsed the signer XML for a name/ID,
but never checked whether the CAdES signature was actually valid. An attacker
could submit a fabricated `signatureDerBase64` with a random certificate PEM,
and the signature count would increment as if a real person had signed. This
completely undermined the integrity of the signature collection system.

**What changed:** Added `verify-signature.ts` using `node-forge` to parse the
PKCS#7 DER structure and Node.js native `crypto` to verify the signature.
The verification performs three checks:

1. **Content integrity:** The `messageDigest` authenticated attribute inside
   the PKCS#7 must match the SHA-256 hash of the submitted content
   (`signerXmlBase64` decoded). This proves the signature was computed over
   the claimed content.

2. **Signature validity:** The authenticated attributes are re-encoded as a
   DER SET and the RSA/ECDSA signature is verified against the signer's
   public key using `crypto.createVerify('SHA256')`. This proves the
   private key holder actually signed.

3. **Certificate consistency:** The SHA-256 fingerprint of the certificate
   embedded in the PKCS#7 structure must match the fingerprint of the
   certificate provided in `signerCertPem`. This prevents submitting a valid
   signature from one certificate while claiming it came from another.

The callback handler now calls `verifyCadesDetached()` before storing the
signature. Invalid signatures are rejected with HTTP 400.

---

### No rate limiting on API endpoints

**Files changed:**
- `webapp/apps/api/src/index.ts`

**What was wrong:** All API endpoints were completely open with no rate
limiting. Any client could create unlimited proposals or submit unlimited
signature callbacks, enabling spam, resource exhaustion, and abuse of the
signature counting system.

**What changed:** Added an in-memory sliding-window rate limiter keyed by
client IP address. Two limiters are applied:

- `POST /api/proposals`: 5 requests per minute per IP
- `POST /api/callback/:requestId`: 30 requests per minute per IP

Exceeding the limit returns HTTP 429 with a `Retry-After` header. Stale
entries are purged every 5 minutes to prevent memory leaks. The rate limiter
is intentionally simple (no Redis dependency) since the portal is typically
a single-instance deployment.

---

### [M-02] `fullText.sha256` hashed the URL, not the document content

**Files changed:**
- `webapp/apps/api/src/index.ts`
- `webapp/apps/api/src/validation.ts`
- `webapp/apps/web/src/types.ts`
- `webapp/apps/web/src/pages/CreateProposalPage.tsx`

**What was wrong:** When creating a proposal, the API computed
`sha256Base64(proposal.fullTextURL)` — hashing the URL string itself, not
the document content at that URL. The field is named `fullText.sha256` and
is intended to bind the signature to a specific document. With the old code,
the document at the URL could be silently replaced after signatures were
collected, and the hash would still appear valid because it only bound to the
URL string.

**What changed:** The API now requires the caller to provide
`fullTextSHA256` — the base64-encoded SHA-256 hash of the actual document
content. The Zod validation schema enforces it as a required non-empty string.
The frontend form includes a new input field for it. The proposal creator is
responsible for computing and submitting the correct content hash, which is
then embedded in the signed manifest.

---

### Non-atomic signature count increment

**Files changed:**
- `webapp/apps/api/src/index.ts`
- `webapp/docker-compose.yml`

**What was wrong:** The callback handler performed two independent database
operations: `SignatureModel.create()` followed by
`ProposalModel.updateOne({ $inc: { signaturesCount: 1 } })`. If the insert
succeeded but the increment failed (network issue, timeout, process crash),
the signature would be stored but the counter would not reflect it. Over time,
the `signaturesCount` would drift below the actual number of signatures, and
the `reachedTarget` status could be permanently incorrect. There was no
reconciliation mechanism.

**What changed:** Both operations are now wrapped in a MongoDB transaction
using `session.withTransaction()`. If either operation fails, the entire
transaction is rolled back — the signature is not stored and the counter is
not incremented. This guarantees the counter always matches the actual number
of signature documents. The `docker-compose.yml` was updated to start MongoDB
with `--replSet rs0` (single-node replica set), which is required for MongoDB
transactions.

---

### Dockerfile runs as root

**Files changed:**
- `webapp/Dockerfile`

**What was wrong:** The runtime stage of the Dockerfile had no `USER`
directive, so the Node.js process ran as root inside the container. If an
attacker exploited a vulnerability in the application, they would have root
privileges in the container, making it easier to escape or pivot.

**What changed:** Added `USER node` before the `CMD` line. The `node` user
is built into the `node:22-bookworm-slim` base image and is the standard
non-root user for Node.js containers.

---

### `issuedAt` not validated against `expiresAt`

**Files changed:**
- `internal/model/validation.go`

**What was wrong:** The `Validate()` function parsed `issuedAt` but discarded
the result (`_, err := time.Parse(...)`). There was no check that `issuedAt`
was before `expiresAt`. A request with `issuedAt: "2099-01-01T00:00:00Z"` and
`expiresAt: "2098-01-01T00:00:00Z"` (issued *after* expiry) would pass
validation. While not directly exploitable, it indicates a malformed or
tampered request that should be rejected.

**What changed:** `issuedAt` is now captured and compared against `expiresAt`.
If `issuedAt` is not strictly before `expiresAt`, validation fails with
`"issuedAt must be before expiresAt"`.

---

### JWK `alg` and `use` fields not validated

**Files changed:**
- `internal/crypto/jwsverify/jwks.go`

**What was wrong:** The `ToPublicKey()` function validated `kty` (must be
`"EC"`) and `crv` (must be `"P-256"`), but ignored the `alg` and `use` fields
entirely. A JWK marked `alg: "RS256"` (RSA algorithm) or `use: "enc"`
(encryption only, not signing) would still be accepted for ES256 signature
verification. While the actual verification would still use ECDSA (so no
algorithm confusion attack is possible), accepting keys with mismatched
metadata is a violation of RFC 7517 and could mask configuration errors.

**What changed:** `ToPublicKey()` now rejects keys where `alg` is present but
not `"ES256"`, or `use` is present but not `"sig"`. Empty/absent values are
still accepted per RFC 7517 (omission means "any use").

---

### MongoDB URI with credentials logged to stdout

**Files changed:**
- `webapp/apps/api/src/index.ts`

**What was wrong:** On startup, the API logged:
`console.log(\`Connected to MongoDB at ${mongoUri}\`)`. If the `MONGODB_URI`
environment variable contained credentials (e.g.,
`mongodb://admin:s3cret@host/db`), the password would appear in plain text
in the logs. Container orchestration systems often collect and store stdout
logs, making this a credential exposure risk.

**What changed:** The URI is parsed as a `URL` object and the password is
replaced with `***` before logging. If the URI cannot be parsed (e.g.,
connection strings without a scheme), a generic `"Connected to MongoDB"`
message is logged instead.

---

### IssuerSerial not populated in ESS-SigningCertificateV2

**Files changed:**
- `internal/crypto/cades/sign.go`

**What was wrong:** The `ESSCertIDv2` structure in the CAdES signature
included the certificate hash but left the `IssuerSerial` field empty. RFC
5035 Section 3 states that `IssuerSerial` SHOULD be present. While the
SHA-256 hash alone is cryptographically sufficient to identify the certificate
(collision resistance makes substitution infeasible), omitting `IssuerSerial`
is a deviation from the standard that could cause interoperability issues with
strict CAdES validators or legal compliance checks.

**What changed:** The `IssuerSerial` field is now populated with the
certificate's issuer distinguished name (DER-encoded RDN sequence) and serial
number (DER-encoded INTEGER). Both are marshaled via Go's `encoding/asn1`
package and set as `asn1.RawValue` fields.

---

### Policy OID and hash parse errors silently ignored

**Files changed:**
- `internal/crypto/cades/sign.go`

**What was wrong:** The signature policy section had three silent error paths:

1. `parseOID(opts.Policy.OID)` — if the OID was malformed, the error was
   checked with `if err == nil` and the entire policy block was skipped.
2. `base64.StdEncoding.DecodeString(opts.Policy.Hash)` — the error was
   discarded with `_, _`.
3. `asn1.Marshal(sigPolicyID)` — the error was checked with `if err == nil`
   and the attribute silently not added.

In all three cases, a malformed policy would produce a signature *without*
the `SignaturePolicyIdentifier` attribute, but no error would be returned to
the caller. The signer would believe they had produced a policy-bound
signature when they had not. For eIDAS compliance, this could mean the
signature does not meet the required legal standard.

**What changed:** All three error paths now return the error to the caller
with descriptive messages (`"invalid policy OID"`, `"invalid policy hash
base64"`, `"failed to marshal signature policy"`). If the policy is present
in the request but cannot be encoded, the signing operation fails rather than
producing a silently non-compliant signature.

---

### Canonical JSON cross-implementation ordering documented

**Files changed:**
- `internal/canon/canon.go`

**What was wrong:** The `Encode()` function's doc comment stated
"Lexicographically sorted keys (Go's default)", which is incorrect. Go's
`encoding/json` outputs struct fields in *declaration order* (the order they
appear in the Go source code), not alphabetically. Map keys are sorted
lexicographically, but the `SignRequest` struct is not a map. The comment
was misleading and the cross-implementation invariant (that the TypeScript
portal must produce JSON with the same field ordering) was not documented
anywhere. If a developer reordered the struct fields or changed the JS object
construction order, JWS verification would break with no obvious explanation.

**What changed:** The doc comment now correctly states "Struct fields in Go
declaration order (NOT alphabetical)" and includes an IMPORTANT note
explaining that the TypeScript portal must construct objects with fields in
the same order. This makes the fragile cross-implementation coupling explicit.

---

## Code quality

---

### Unhandled errors across the codebase

**Files changed:**
- `internal/storage/audit.go`
- `internal/crypto/pkcs12store/signer_p11.go`
- `internal/crypto/pkcs12store/store_impl.go`
- `internal/crypto/systemstore/nss.go`
- `internal/crypto/systemstore/nss_profiles.go`
- `internal/crypto/systemstore/p12_scan.go`
- `internal/crypto/jwsverify/jwks.go`
- `internal/net/fetch_request.go`
- `internal/net/release.go`
- `internal/net/submit.go`
- `internal/ui/screens/certificates.go`
- `internal/ui/screens/request_details.go`
- `test/integration_test.go`
- `test/unit_test.go`
- `tools/collector/main.go`

**What was wrong:** 26 return values from error-producing functions were
silently discarded across the codebase. The linter (`errcheck`) flagged all
of them. Categories included:

- `defer f.Close()` on files opened for writing — close flushes buffered data,
  so a close error means data may not have been persisted.
- `defer resp.Body.Close()` on HTTP responses — read-only, but still
  technically an unchecked error.
- `os.Remove()` during cleanup on error paths — if cleanup fails, orphaned
  files are left behind with no indication.
- `os.Setenv()` — could fail due to invalid key or system limits.
- PKCS#11 `p.Finalize()` and `p.CloseSession()` — hardware token cleanup
  failures were invisible.
- `Store.Delete()` and `AuditLogger.Log()` in UI goroutines — errors from
  these operations were silently swallowed.
- `json.NewEncoder(w).Encode()` in HTTP handlers — write failures to the
  response were ignored.

**What changed:** Each error is now handled according to its context:

- **Write file closes** (`audit.go` Log): The file is explicitly closed (not
  deferred) and the close error is returned to the caller. This ensures audit
  entries are actually flushed to disk.
- **Read file closes** (`audit.go` ReadAll, `nss_profiles.go`, `p12_scan.go`,
  test files): Close errors are logged as warnings. Read-only closes almost
  never fail, but if they do it's now visible.
- **HTTP response body closes** (`fetch_request.go`, `submit.go`,
  `release.go`, `jwks.go`): Wrapped in `defer func()` to satisfy the linter.
  These are read-only and the error is not actionable.
- **PKCS#11 cleanup** (`signer_p11.go`, `nss.go`): `p.Finalize()`,
  `p.CloseSession()`, and `p.Login()` errors are now logged as warnings.
  These are cleanup operations that should not fail silently since they may
  indicate hardware token issues.
- **`os.Setenv`** (`signer_p11.go`, `nss.go`): Errors are returned to the
  caller — failing to set `NSS_CONFIG_DIR` would cause the subsequent
  PKCS#11 initialization to behave incorrectly.
- **`os.Remove` cleanup** (`store_impl.go`): Cleanup failures during Import
  are logged with the file path. The `Delete()` method now returns a combined
  error from both remove operations (ignoring `ErrNotExist`).
- **UI goroutines** (`certificates.go`, `request_details.go`): `Store.Delete`
  and `AuditLogger.Log` errors are logged with `log.Printf`.
- **HTTP handlers** (`tools/collector/main.go`): `json.Encode` errors are
  logged. `t.Execute` error was already fixed to return HTTP 500.

---

### Deprecated `elliptic.IsOnCurve` replaced

**Files changed:**
- `internal/crypto/jwsverify/jwks.go`

**What was wrong:** `ToPublicKey()` used `elliptic.P256().IsOnCurve(x, y)` to
validate that an EC point is on the curve. This function has been deprecated
since Go 1.21 as a "low-level unsafe API". The deprecation notice recommends
using `crypto/ecdh` instead.

**What changed:** On-curve validation now uses `ecdh.P256().NewPublicKey()`,
which accepts the same uncompressed point encoding and performs the same
validation internally. The validated coordinates are then used to construct
an `ecdsa.PublicKey` directly via `big.Int.SetBytes()` for use in signature
verification.

---

### Unused functions removed

**Files changed:**
- `internal/ui/screens/wizard.go`

**What was wrong:** Five functions (`centeredMax`, `exactWidthPx`,
`centeredLabel`, `centeredCaption`, `minInt`) were defined but never called
anywhere in the codebase.

**What changed:** All five functions were deleted.

---

### Style fixes

**Files changed:**
- `internal/crypto/systemstore/nss_profiles.go`
- `tools/collector/main.go`

**What changed:**
- `strings.HasPrefix(line, prefix)` + `strings.TrimPrefix(line, prefix)`
  replaced with `strings.CutPrefix(line, prefix)` for cleaner single-call
  pattern.
- `map[string]interface{}` replaced with `map[string]any` (Go 1.18+
  idiomatic style).

---

## Production hardening (idCAT / AOC compatibility)

---

### Signer ID type hardcoded to "DNI"

**Files changed:**
- `internal/crypto/certs/extract.go`
- `internal/crypto/certs/extract_test.go`
- `internal/ui/screens/request_details.go`

**What was wrong:** The ILP XML generation always set `TipusIdentificador`
to `"DNI"`, regardless of the actual ID type in the certificate. Spanish
certificates can contain three different identifier types:

- **DNI** (Documento Nacional de Identidad) — 8 digits + letter
- **NIE** (Número de Identidad de Extranjero) — X/Y/Z + 7 digits + letter
- **CIF** (Código de Identificación Fiscal) — letter + 7 digits + check

When a foreign resident signed with an idCAT certificate containing a NIE,
the XML would incorrectly claim the identifier type was "DNI". This is a
legal compliance issue — the generated ILP XML would not accurately represent
the signer's identification, potentially invalidating the signature for
Catalan administrative procedures.

**What changed:** The `extractID()` function now returns both the ID value
and its type (`"DNI"`, `"NIE"`, or `"CIF"`) based on which regex pattern
matched. A new `IDType` field was added to the `ExtractedInfo` struct to
carry this information through the extraction pipeline. The UI signing flow
reads `IDType` from the extracted certificate info and passes it to the ILP
XML generator, falling back to `"DNI"` only if the type could not be
determined. A new test case verifies NIE detection with a certificate
containing `X1234567A` in the serialNumber field.

---

### No certificate validation before signing

**Files changed:**
- `internal/crypto/certs/validate.go` (new)
- `internal/crypto/certs/validate_test.go` (new)
- `internal/ui/screens/request_details.go`

**What was wrong:** The signing flow accepted any imported certificate
without checking whether it was actually suitable for digital signatures.
An expired certificate, a not-yet-valid certificate, a certificate without
the `DigitalSignature` key usage flag, or a certificate with a weak RSA key
could all be used to produce signatures. For a production system handling
legally-binding signatures, this is unacceptable:

- Expired certificate signatures are rejected by most validators and have
  no legal standing.
- Not-yet-valid certificates indicate clock skew or a misconfigured CA.
- Certificates without `DigitalSignature` key usage are explicitly not
  intended for signing per X.509 semantics.
- RSA keys below 2048 bits are considered cryptographically weak by NIST
  (SP 800-131A) and most European qualified trust service providers.

**What changed:** A new `ValidateForSigning(cert)` function performs four
checks before any signing operation:

1. **Time validity**: `NotBefore` must be in the past, `NotAfter` must be
   in the future. Rejects expired and not-yet-valid certificates with clear
   error messages including the relevant timestamp.
2. **Key usage**: If the certificate's `KeyUsage` field is set, it must
   include `DigitalSignature`. Certificates intended only for key
   encipherment or other purposes are rejected.
3. **Key type**: Only RSA and ECDSA public keys are accepted. These are the
   two types supported by the CAdES signing code and by idCAT certificates.
4. **RSA key size**: RSA keys must be at least 2048 bits. Keys of 1024 bits
   or smaller are rejected.

The validation is called in the UI signing flow immediately before launching
the signing goroutine. If validation fails, the user sees a clear status
message and signing does not proceed. Five tests cover the valid case and
each rejection path.

---

### CAdES signatures used SHA-1 message digest

**Files changed:**
- `internal/crypto/cades/sign.go`
- `webapp/apps/api/src/verify-signature.ts`

**What was wrong:** The Go `smallstep/pkcs7` library defaults to SHA-1 for
the PKCS#7 message digest algorithm. SHA-1 has been broken for collision
resistance since 2017 (SHAttered attack). All CAdES signatures produced by
VocSign were using SHA-1 for the content digest, despite the
`SigningCertificateV2` attribute using SHA-256 for the certificate hash.
This is inconsistent and below modern security standards. European qualified
signature regulations (eIDAS) and ETSI standards recommend SHA-256 or
stronger.

**What changed:** The Go signing code now explicitly calls
`sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)` after creating the
`SignedData` structure, forcing SHA-256 for the message digest. The Node.js
server-side verifier reads the digest algorithm OID from the PKCS#7 structure
rather than hardcoding it, and rejects SHA-1 signatures — only SHA-256,
SHA-384, and SHA-512 are accepted.

---

## Adversarial hardening (production readiness)

---

### Server-side certificate issuer whitelist

**Files changed:**
- `webapp/apps/api/src/verify-signature.ts`

**What was wrong:** The server verified the CAdES signature math
(messageDigest, authenticated attributes, certificate fingerprint) but never
checked whether the signing certificate was issued by a recognized Spanish
certificate authority. An attacker could generate a self-signed certificate
with any name and DNI, sign arbitrary XML, and submit it — the server would
accept it. This completely undermined the system's purpose.

**What changed:** A `validateSignerCertificate()` function now checks every
submitted signature's certificate for:

1. **Validity period**: Expired or not-yet-valid certificates are rejected.
2. **Key usage**: If present, must include `digitalSignature`.
3. **Issuer whitelist**: The certificate issuer must contain one of the
   recognized Spanish/Catalan CA names (AC FNMT, FNMT-RCM, EC-Ciutadania,
   EC-idCAT, EC-SectorPublic, EC-AL, Agencia Catalana de Certificacio,
   Consorci AOC, ACCV, IZENPE, ANF AC). Unrecognized issuers are rejected.

An `ALLOW_TEST_CERTS=true` environment variable skips issuer validation for
development and testing environments.

---

### Server-side identity cross-check

**Files changed:**
- `webapp/apps/api/src/cert-identity.ts` (new)
- `webapp/apps/api/src/index.ts`

**What was wrong:** The signer identity (DNI/NIE, name) used for
deduplication was extracted solely from the attacker-controlled XML content.
The certificate's Subject DN was never compared against the XML claims. An
attacker could sign with their own certificate but submit XML claiming to
be a different person, inflating signature counts with fabricated identities.

**What changed:** A new `extractCertIdentity()` function parses the
certificate's Subject DN to extract the `serialNumber` field (stripping
IDCES-/IDESP- prefixes) and validates it as a DNI, NIE, or CIF. The
callback handler now compares the certificate-extracted `signerId` against
the XML-extracted `signerId` and rejects the submission with HTTP 400 if
they don't match.

---

### Identity fields locked in desktop UI

**Files changed:**
- `internal/ui/screens/request_details.go`

**What was wrong:** After selecting a certificate, the name and DNI form
fields were editable. A user could select their own certificate but manually
type a different person's name and DNI. The signed ILP XML would contain the
typed values, not the certificate's, creating an identity mismatch.

**What changed:** The `NomEditor`, `Cognom1Editor`, `Cognom2Editor`, and
`DNIEditor` are now set to `ReadOnly = true` in the constructor. The values
are populated exclusively from the certificate's Subject DN via
`ExtractSpanishIdentity()` and cannot be modified by the user.

---

### API key authentication for proposal creation

**Files changed:**
- `webapp/apps/api/src/index.ts`
- `webapp/.env.example`

**What was wrong:** The `POST /api/proposals` endpoint had no authentication.
Anyone could create proposals that would receive a valid organizer JWS
signature from the server, making phishing proposals indistinguishable from
legitimate ones.

**What changed:** An `authRequired` middleware checks the `Authorization:
Bearer <key>` header against the `ORGANIZER_API_KEY` environment variable
using `crypto.timingSafeEqual` (constant-time comparison to prevent timing
attacks). When the key is not configured, unauthenticated access is allowed
for development convenience, and a warning is logged at startup.

---

### RFC 3161 trusted timestamp support (CAdES-T)

**Files changed:**
- `internal/crypto/cades/timestamp.go` (new)
- `internal/model/response.go`
- `internal/ui/screens/request_details.go`
- `webapp/apps/api/src/validation.ts`
- `webapp/apps/api/src/models.ts`

**What was wrong:** Signatures had no trusted timestamp. The signing-time
attribute is present (added automatically by the pkcs7 library with the
signer's local clock), but this is not a trusted timestamp — the signer
controls their system clock. Without a timestamp from a Timestamp Authority
(TSA), it is impossible to prove that a signature was created within the
ILP collection period (Llei 1/2006 art. 7, typically 120 days).

**What changed:** A new `RequestTimestamp()` function in `timestamp.go`
implements the RFC 3161 protocol: it hashes the CAdES signature value with
SHA-256, constructs a `TimeStampReq`, sends it to a TSA via HTTP POST, and
parses the `TimeStampResp` to extract the `TimeStampToken`. The desktop
client reads the TSA URL from the `VOCSIGN_TSA_URL` environment variable and
requests a timestamp after each successful signing. The token is
base64-encoded and included in the `SignResponse` as
`timestampTokenBase64`. The server stores it alongside the signature in
MongoDB. When `VOCSIGN_TSA_URL` is not configured, signing proceeds without
a timestamp (CAdES-BES level).

---

### OCSP certificate revocation checking

**Files changed:**
- `internal/crypto/certs/validate.go`

**What was wrong:** The certificate validation checked time validity, key
usage, key type, and key size, but never checked whether the certificate had
been revoked. A signer with a revoked certificate could still produce valid
signatures. In a legal dispute, the signer could claim their certificate was
compromised and revoked before the signature was made.

**What changed:** `ValidateForSigning()` now accepts issuer certificates and
calls a new `CheckRevocation()` function. It extracts the OCSP responder URL
from the certificate's `OCSPServer` extension, creates an OCSP request via
`golang.org/x/crypto/ocsp`, sends it to the responder with a 10-second
timeout, and checks the response status. Revoked certificates are rejected
with an error including the revocation timestamp. If no OCSP URL is
available (not all certificates have one), a warning is logged and signing
proceeds.

---

### GDPR consent and right-to-erasure

**Files changed:**
- `internal/ui/screens/request_details.go`
- `webapp/apps/api/src/index.ts`

**What was wrong:** No consent mechanism existed for data protection. The
desktop client collected personal data (name, DNI, birth date, certificate)
and transmitted it to the server without any GDPR-compliant consent
indication. No mechanism existed for citizens to exercise their right to
erasure (GDPR Art. 17).

**What changed:**

1. **Consent checkbox**: A `ConsentCheck` widget is rendered in the signing
   form. The text reads: "I confirm I have read the proposal, accept the
   data protection notice, and consent to supporting this legislative
   initiative." Signing is blocked unless the checkbox is checked.

2. **Right-to-erasure endpoint**: A new `DELETE /api/signatures/:signerId`
   endpoint (API-key protected) deletes all signatures for a given signer
   ID and recalculates the affected proposals' signature counts.

---

### CORS restricted to portal origin

**Files changed:**
- `webapp/apps/api/src/index.ts`

**What was wrong:** `app.use(cors())` set `Access-Control-Allow-Origin: *`,
allowing any website to call the API from a user's browser. A malicious site
could enumerate proposals, create fake proposals (before auth was added), or
consume victims' rate limit quotas.

**What changed:** CORS is now configured with `origin: publicBaseURL` and
`methods: ['GET', 'POST']`, restricting browser-based requests to the
portal's own domain. The desktop client is unaffected since CORS is only
enforced by browsers.

---

### Tamper-evident audit log with hash chain

**Files changed:**
- `internal/storage/audit.go`
- `internal/storage/audit_test.go`

**What was wrong:** The audit log (`audit.jsonl`) was a plain text file with
no integrity protection. Any party with filesystem access could add, modify,
or delete entries undetectably. For legal evidence purposes, the audit trail
must provide tamper detection.

**What changed:** Each `AuditEntry` now includes a `PrevHash` field
containing the SHA-256 hex digest of the previous entry's JSON bytes,
forming a hash chain. The first entry has an empty `PrevHash`. The
`AuditLogger` tracks the last hash in memory and reconstructs it from the
file on startup via `loadLastHash()` to ensure chain continuity across
process restarts. A new `Verify()` method reads all entries and validates
the chain — returning the count on success or the index and error on the
first mismatch. Two new tests verify the chain works correctly and detects
tampering.

---

### Document hash verification before signing

**Files changed:**
- `internal/net/verify_document.go` (new)
- `internal/net/verify_document_test.go` (new)
- `internal/ui/screens/request_details.go`

**What was wrong:** The proposal manifest includes `fullText.url` and
`fullText.sha256`, but neither the desktop client nor the server ever
downloaded the document and verified it matched the hash. A proposal creator
could change the document at the URL after signatures were collected, and no
one would detect the change.

**What changed:** A new `VerifyDocumentHash()` function downloads the
document from the manifest URL (using the safe HTTP client with redirect
checking and body size limits), computes its SHA-256, and compares against
the hash in the manifest. The desktop client now calls this function as the
first step of the signing flow, before certificate unlocking or XML
generation. If the hash doesn't match, signing is aborted with a clear
error message showing both hashes. Three tests cover match, mismatch, and
unreachable URL scenarios.

---

### Input validation hardening

**Files changed:**
- `webapp/apps/api/src/validation.ts`
- `webapp/.env.example`

**What was wrong:** The Zod validation schemas accepted unbounded string
lengths for most fields. The `fullTextSHA256` field only required a
non-empty string with no format validation. The `targetSignatures` field had
no upper bound. These gaps enabled CPU-intensive operations on oversized
payloads.

**What changed:**

- `fullTextSHA256` and `payloadCanonicalSha256` now require a base64-encoded
  SHA-256 hash (regex-validated, exactly 43-44 characters).
- `signatureDerBase64` limited to 100 KB, `signerCertPem` to 20 KB,
  `signerXmlBase64` to 50 KB, certificate chain to 10 entries of 20 KB each.
- Proposal fields limited: title/promoter 500 chars, jurisdiction 200 chars,
  summary/legalStatement 10,000 chars.
- `targetSignatures` capped at 10,000,000.
- `.env.example` updated with `ALLOW_TEST_CERTS` and `VOCSIGN_RELEASE_BASE_URL`
  documentation.
- `fullTextSHA256` and `payloadCanonicalSha256` now also verified via
  `.refine()` to decode to exactly 32 bytes, not just regex.

---

### HTTP security headers

**Files changed:**
- `webapp/apps/api/src/index.ts`

**What was wrong:** The Express app returned no security headers. Browsers
use these headers to enable built-in protections against clickjacking,
MIME-type sniffing, and cross-site attacks.

**What changed:** A middleware sets `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `X-XSS-Protection: 0` (disables flawed legacy
filter), and `Referrer-Policy: strict-origin-when-cross-origin` on every
response. No external dependency (helmet) was added.

---

### Error details no longer leaked to clients

**Files changed:**
- `webapp/apps/api/src/index.ts`

**What was wrong:** The callback handler returned raw `err.message` strings
from `node-forge` ASN.1 parsing and `X509Certificate` failures in the
`details` field of error responses. These could reveal internal library
versions, ASN.1 structure details, and file paths that aid attacker
reconnaissance.

**What changed:** Error catch blocks now log the full error server-side via
`console.error()` and return only a generic error message to the client. The
`details` field was removed from the signature verification and certificate
identity error responses.

---

### Server-side `signedAt` timestamp validation

**Files changed:**
- `webapp/apps/api/src/index.ts`

**What was wrong:** The `signedAt` field in the signature response was
accepted verbatim from the client with no validation against the server's
clock. A signer could submit a timestamp claiming they signed years in the
past or in the future, which could be used to circumvent ILP collection
period requirements.

**What changed:** The callback handler now validates `signedAt` against the
server's current time. Submissions are rejected if the timestamp is more
than 5 minutes in the future (clock skew tolerance) or more than 24 hours
in the past.

---

### Timestamp computed over correct input (signature value)

**Files changed:**
- `internal/crypto/cades/timestamp.go`
- `internal/crypto/cades/timestamp_test.go` (new)

**What was wrong:** The RFC 3161 timestamp request was being computed over
the entire PKCS#7 DER output. Per ETSI EN 319 122-1 section 5.4, the
timestamp must be computed over the `EncryptedDigest` (signature value) from
the SignerInfo — not the entire PKCS#7 structure. Using the full blob would
produce a timestamp that CAdES-T validators would not recognize.

**What changed:** `RequestTimestamp()` now internally calls
`extractSignatureValue()`, which parses the PKCS#7 ASN.1 structure to locate
the `EncryptedDigest` OCTET STRING in the first SignerInfo. The timestamp is
computed over this extracted value. A unit test verifies correct extraction
(256-byte RSA signature from a 1266-byte PKCS#7 structure).

---

### Server-side certificate chain verification, OCSP/CRL revocation with LTV

**Files changed:**
- `webapp/apps/api/src/ca-certs/*.pem` (new — 5 files, 20 certificates)
- `webapp/apps/api/src/ca-trust.ts` (new)
- `webapp/apps/api/src/safe-fetch.ts` (new)
- `webapp/apps/api/src/chain-verify.ts` (new)
- `webapp/apps/api/src/revocation.ts` (new)
- `webapp/apps/api/src/verify-signature.ts`
- `webapp/apps/api/src/index.ts`
- `webapp/apps/api/package.json`

**What was wrong:** The server validated signer certificates only by checking
the issuer name against a hardcoded string whitelist (`ACCEPTED_ISSUERS`
substring matching). There was no cryptographic chain verification against
trusted CA roots, no OCSP revocation checking, and no CRL fallback. This
meant:

- A self-signed certificate with a forged issuer CN containing "FNMT" would
  pass validation.
- A certificate that had been revoked by its CA would be accepted.
- No chain-of-trust was verified between the signer cert and a recognized
  root CA.

For legal validity under eIDAS (Regulation EU 910/2014) and Spanish
electronic signature law, the server — as the trust boundary — must
cryptographically verify the full certificate chain and confirm the
certificate has not been revoked.

**What changed:**

1. **Bundled Spanish CA trust store**: Root and intermediate certificates
   from 5 qualified Spanish CAs (FNMT-RCM, Consorci AOC/CATCert, ACCV,
   IZENPE, ANF AC) are bundled as PEM files in `ca-certs/`. A `ca-trust.ts`
   module loads them at startup, classifying as roots (self-signed) or
   intermediates. Total: 20 certificates covering both legacy and new eIDAS
   hierarchies.

2. **Cryptographic chain verification** (`chain-verify.ts`): Builds a
   certificate chain from the signer cert to a trusted root using the
   client-provided chain PEMs, bundled intermediates, and bundled roots.
   Each link is verified cryptographically via `X509Certificate.verify()`.
   Intermediates must have `CA:true` basic constraint. Maximum chain depth:
   5. Expired certificates in the chain are rejected.

3. **OCSP revocation checking** (`revocation.ts`): Extracts the OCSP
   responder URL from the certificate's Authority Information Access
   extension. Builds a proper OCSP request per RFC 6960 (SHA-1 hash of
   DER-encoded issuer DN and public key BIT STRING value — not the
   human-readable strings). Verifies the OCSP response signature against
   the issuer's public key via WebCrypto. Checks response freshness
   (`thisUpdate` < 48h, `nextUpdate` in future).

4. **CRL fallback**: If OCSP fails or returns Unknown, extracts the CRL
   Distribution Point URL via `@peculiar/x509`, fetches the CRL (max 10 MB),
   verifies its signature against the issuer, and checks the revoked
   certificates list.

5. **Long-Term Validation (LTV)**: Both OCSP and CRL revocation checks
   compare the revocation timestamp against `signedAt`. If the certificate
   was revoked *after* the signature was created (`revokedAt > signedAt`),
   the signature is still valid — it was made while the certificate was
   active. Only certificates revoked *before* signing are rejected. This
   aligns with eIDAS Article 32 requirements for validation of qualified
   electronic signatures.

6. **Hard-fail policy**: If neither OCSP nor CRL can confirm non-revocation
   (no URLs available, network errors, timeouts), the signature is rejected.

7. **SSRF-safe HTTP client** (`safe-fetch.ts`): OCSP/CRL URLs come from
   certificates and could be attacker-controlled. The HTTP client blocks
   requests to private/internal IP ranges (127.0.0.0/8, 10.0.0.0/8,
   172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, ::1, fc00::/7),
   enforces response size limits (1 MB for OCSP, 10 MB for CRL), and
   applies a 10-second timeout.

8. **`ACCEPTED_ISSUERS` retained**: The issuer name allowlist is kept as
   a secondary enforcement layer and human-readable registry of accepted
   CAs. Even with a valid chain to a bundled root, the issuer CN must also
   appear in the list.

9. **`ALLOW_TEST_CERTS` startup warning**: When the bypass is active, a
   warning is logged at startup to prevent accidental production use.

The `validateSignerCertificate()` and `verifyCadesDetached()` functions are
now async (OCSP/CRL involve network calls). The validation pipeline runs:
expiration → key usage → issuer allowlist → chain verification → revocation
check with LTV.
