import { X509Certificate, createHash } from 'node:crypto';
import { AsnConvert } from '@peculiar/asn1-schema';
import {
  OCSPRequest, OCSPResponse, BasicOCSPResponse, OCSPResponseStatus,
  CertID, TBSRequest, Request as OCSPRequestEntry,
} from '@peculiar/asn1-ocsp';
import { AlgorithmIdentifier, Certificate } from '@peculiar/asn1-x509';
import { OctetString } from '@peculiar/asn1-schema';
import { safeFetch, type SafeFetchOpts } from './safe-fetch.js';

// SHA-1 OID used in OCSP CertID
const SHA1_OID = '1.3.14.3.2.26';

// OCSP response type OID: id-pkix-ocsp-basic
const OCSP_BASIC_OID = '1.3.6.1.5.5.7.48.1.1';

// Maximum freshness for OCSP thisUpdate (48 hours)
const OCSP_MAX_AGE_MS = 48 * 60 * 60 * 1000;

export interface RevocationOpts {
  allowLocalhost?: boolean;
  timeoutMs?: number;
}

/**
 * Custom error for certificate revocation. We tag it so we can
 * re-throw immediately without falling through to the next method.
 */
class RevokedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RevokedError';
  }
}

/**
 * Check revocation status of a certificate via OCSP (primary) then CRL (fallback).
 * Hard-fail: if neither method can confirm non-revocation, throws.
 *
 * @param cert   The end-entity certificate to check
 * @param issuer The direct issuer certificate
 * @param signedAt ISO 8601 timestamp of when the signature was created (for LTV)
 * @param opts   Options passed through to safeFetch
 */
export async function checkRevocation(
  cert: X509Certificate,
  issuer: X509Certificate,
  signedAt: string,
  opts?: RevocationOpts
): Promise<void> {
  const fetchOpts: SafeFetchOpts = {
    allowLocalhost: opts?.allowLocalhost,
    timeoutMs: opts?.timeoutMs,
  };
  const signedAtDate = new Date(signedAt);

  const errors: string[] = [];

  // --- Try OCSP first ---
  const ocspUrl = extractOcspUrl(cert);
  if (ocspUrl) {
    try {
      await checkOCSP(cert, issuer, signedAtDate, ocspUrl, fetchOpts);
      return; // OCSP confirmed non-revocation (or LTV pass)
    } catch (err) {
      if (err instanceof RevokedError) throw err;
      // OCSP returned "unknown" or had an error — fall through to CRL
      errors.push(`OCSP: ${(err as Error).message}`);
    }
  } else {
    errors.push('OCSP: no responder URL in certificate');
  }

  // --- Try CRL fallback ---
  const crlUrls = await extractCrlUrls(cert);
  if (crlUrls.length > 0) {
    for (const crlUrl of crlUrls) {
      try {
        await checkCRL(cert, issuer, signedAtDate, crlUrl, fetchOpts);
        return; // CRL confirmed non-revocation (or LTV pass)
      } catch (err) {
        if (err instanceof RevokedError) throw err;
        errors.push(`CRL (${crlUrl}): ${(err as Error).message}`);
      }
    }
  } else {
    errors.push('CRL: no distribution point URLs in certificate');
  }

  // Hard-fail: neither method could confirm non-revocation
  throw new Error(
    `Revocation check failed (hard-fail): ${errors.join('; ')}`
  );
}

/* ------------------------------------------------------------------ */
/*  OCSP                                                               */
/* ------------------------------------------------------------------ */

/**
 * Extract the OCSP responder URL from the cert's Authority Information Access extension.
 * Node.js X509Certificate.infoAccess returns a string like:
 *   "OCSP - URI:http://ocsp.example.com\nCA Issuers - URI:http://..."
 */
function extractOcspUrl(cert: X509Certificate): string | null {
  const infoAccess = cert.infoAccess;
  if (!infoAccess) return null;

  // infoAccess is a string with entries separated by \n
  const lines = infoAccess.split('\n');
  for (const line of lines) {
    const match = line.match(/^OCSP\s*-\s*URI:(.+)$/);
    if (match) return match[1].trim();
  }
  return null;
}

/**
 * Build an OCSP request, send it, parse and verify the response.
 */
async function checkOCSP(
  cert: X509Certificate,
  issuer: X509Certificate,
  signedAtDate: Date,
  ocspUrl: string,
  fetchOpts: SafeFetchOpts
): Promise<void> {
  // --- Build OCSP request ---

  // Parse the leaf cert's DER to get issuer DN
  const certDer = cert.raw;
  const asnCert = AsnConvert.parse(certDer, Certificate);

  // issuerNameHash: SHA-1 of DER-encoded issuer DN from the leaf cert
  const issuerNameDer = AsnConvert.serialize(asnCert.tbsCertificate.issuer);
  const issuerNameHash = createHash('sha1').update(Buffer.from(issuerNameDer)).digest();

  // issuerKeyHash: SHA-1 of the BIT STRING value (raw public key bytes) from issuer's SPKI
  const issuerAsnCert = AsnConvert.parse(issuer.raw, Certificate);
  const issuerPubKeyBits = issuerAsnCert.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey;
  const issuerKeyHash = createHash('sha1').update(Buffer.from(issuerPubKeyBits)).digest();

  // Serial number: Node.js format is uppercase hex with colons, e.g. "01:AB:CD"
  const serialHex = cert.serialNumber.replace(/:/g, '');
  const serialBytes = Buffer.from(serialHex, 'hex');

  const certId = new CertID({
    hashAlgorithm: new AlgorithmIdentifier({ algorithm: SHA1_OID, parameters: null }),
    issuerNameHash: new OctetString(issuerNameHash),
    issuerKeyHash: new OctetString(issuerKeyHash),
    serialNumber: serialBytes.buffer.slice(
      serialBytes.byteOffset,
      serialBytes.byteOffset + serialBytes.byteLength
    ),
  });

  const ocspReq = new OCSPRequest({
    tbsRequest: new TBSRequest({
      requestList: [
        new OCSPRequestEntry({ reqCert: certId }),
      ],
    }),
  });

  const reqDer = AsnConvert.serialize(ocspReq);

  // --- Send OCSP request ---
  const responseBytes = await safeFetch(ocspUrl, {
    ...fetchOpts,
    method: 'POST',
    body: Buffer.from(reqDer),
    contentType: 'application/ocsp-request',
  });

  // --- Parse OCSP response ---
  const ocspResp = AsnConvert.parse(responseBytes, OCSPResponse);

  if (ocspResp.responseStatus !== OCSPResponseStatus.successful) {
    throw new Error(`OCSP responder returned status ${ocspResp.responseStatus}`);
  }

  if (!ocspResp.responseBytes) {
    throw new Error('OCSP response has no responseBytes');
  }

  if (ocspResp.responseBytes.responseType !== OCSP_BASIC_OID) {
    throw new Error(`Unsupported OCSP response type: ${ocspResp.responseBytes.responseType}`);
  }

  const basicResp = AsnConvert.parse(
    ocspResp.responseBytes.response.buffer,
    BasicOCSPResponse
  );

  // --- Verify OCSP response signature ---
  await verifyOcspSignature(basicResp, issuer);

  // --- Find our cert's SingleResponse ---
  const responses = basicResp.tbsResponseData.responses;
  if (!responses || responses.length === 0) {
    throw new Error('OCSP response contains no SingleResponse entries');
  }

  // Match by serial number
  const singleResp = responses.find((r) => {
    const respSerial = Buffer.from(r.certID.serialNumber).toString('hex');
    return respSerial.toLowerCase() === serialHex.toLowerCase();
  });

  if (!singleResp) {
    throw new Error('OCSP response does not contain a response for our certificate');
  }

  // --- Check freshness ---
  const now = new Date();
  const thisUpdate = singleResp.thisUpdate;
  const ageMs = now.getTime() - thisUpdate.getTime();
  if (ageMs > OCSP_MAX_AGE_MS) {
    throw new Error(
      `OCSP response too old: thisUpdate was ${thisUpdate.toISOString()} (${Math.round(ageMs / 3600000)}h ago)`
    );
  }

  if (singleResp.nextUpdate && singleResp.nextUpdate < now) {
    throw new Error(
      `OCSP response expired: nextUpdate was ${singleResp.nextUpdate.toISOString()}`
    );
  }

  // --- Check status ---
  const status = singleResp.certStatus;

  // CertStatus is a CHOICE: good (null), revoked (RevokedInfo), unknown (null)
  if (status.good !== undefined) {
    return; // Certificate is not revoked
  }

  if (status.revoked) {
    const revokedAt = status.revoked.revocationTime;
    // LTV: if revoked after signing, the cert was valid at signing time
    if (revokedAt > signedAtDate) {
      return; // Cert was valid when the signature was created
    }
    throw new RevokedError(
      `Certificate was revoked at ${revokedAt.toISOString()}, before signing at ${signedAtDate.toISOString()}`
    );
  }

  // status.unknown — fall through to CRL
  throw new Error('OCSP status is "unknown" for this certificate');
}

/**
 * Verify the OCSP response signature against the issuer's public key.
 */
async function verifyOcspSignature(
  basicResp: BasicOCSPResponse,
  issuer: X509Certificate
): Promise<void> {
  const tbsRaw = basicResp.tbsResponseDataRaw;
  if (!tbsRaw) {
    throw new Error('OCSP response missing tbsResponseData raw bytes');
  }

  const sigAlgOid = basicResp.signatureAlgorithm.algorithm;
  const sigBytes = basicResp.signature;

  // Map OID to WebCrypto algorithm
  const algorithm = oidToWebCryptoAlg(sigAlgOid);

  // Import the issuer's public key
  const issuerKey = await importIssuerPublicKey(issuer, algorithm);

  const valid = await globalThis.crypto.subtle.verify(
    algorithm,
    issuerKey,
    sigBytes,
    tbsRaw
  );

  if (!valid) {
    throw new Error('OCSP response signature verification failed');
  }
}

/**
 * Map common signature algorithm OIDs to WebCrypto verify parameters.
 */
function oidToWebCryptoAlg(oid: string): RsaPssParams | EcdsaParams | Algorithm {
  switch (oid) {
    // RSA PKCS#1 v1.5
    case '1.2.840.113549.1.1.5':  // sha1WithRSAEncryption
      return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-1' } as Algorithm;
    case '1.2.840.113549.1.1.11': // sha256WithRSAEncryption
      return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } as Algorithm;
    case '1.2.840.113549.1.1.12': // sha384WithRSAEncryption
      return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' } as Algorithm;
    case '1.2.840.113549.1.1.13': // sha512WithRSAEncryption
      return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' } as Algorithm;
    // ECDSA
    case '1.2.840.10045.4.3.2':   // ecdsa-with-SHA256
      return { name: 'ECDSA', hash: 'SHA-256' } as EcdsaParams;
    case '1.2.840.10045.4.3.3':   // ecdsa-with-SHA384
      return { name: 'ECDSA', hash: 'SHA-384' } as EcdsaParams;
    case '1.2.840.10045.4.3.4':   // ecdsa-with-SHA512
      return { name: 'ECDSA', hash: 'SHA-512' } as EcdsaParams;
    // RSA-PSS
    case '1.2.840.113549.1.1.10': // RSASSA-PSS
      // For PSS we default to SHA-256; real usage would parse parameters
      return { name: 'RSA-PSS', saltLength: 32, hash: 'SHA-256' } as unknown as RsaPssParams;
    default:
      throw new Error(`Unsupported OCSP signature algorithm OID: ${oid}`);
  }
}

/**
 * Import the issuer's public key as a CryptoKey for WebCrypto verify.
 */
async function importIssuerPublicKey(
  issuer: X509Certificate,
  algorithm: Algorithm | RsaPssParams | EcdsaParams
): Promise<CryptoKey> {
  // Get the issuer's SPKI DER
  const issuerAsnCert = AsnConvert.parse(issuer.raw, Certificate);
  const spkiDer = AsnConvert.serialize(issuerAsnCert.tbsCertificate.subjectPublicKeyInfo);

  const algName = (algorithm as { name: string }).name;

  // Determine import algorithm
  let importAlg: RsaHashedImportParams | EcKeyImportParams | Algorithm;
  if (algName === 'RSASSA-PKCS1-v1_5' || algName === 'RSA-PSS') {
    importAlg = {
      name: algName,
      hash: (algorithm as { hash: string }).hash || 'SHA-256',
    } as RsaHashedImportParams;
  } else if (algName === 'ECDSA') {
    // Detect the curve from the SPKI
    const paramsRaw = issuerAsnCert.tbsCertificate.subjectPublicKeyInfo.algorithm.parameters;
    let namedCurve = 'P-256';
    if (paramsRaw) {
      // The parameters field for EC keys is the curve OID
      // We need to parse it; it's a raw OID
      const curveOidHex = Buffer.from(paramsRaw).toString('hex');
      // Common EC curve OIDs (DER-encoded OID values)
      if (curveOidHex.includes('2a8648ce3d030107')) namedCurve = 'P-256';
      else if (curveOidHex.includes('2b81040022')) namedCurve = 'P-384';
      else if (curveOidHex.includes('2b81040023')) namedCurve = 'P-521';
    }
    importAlg = { name: 'ECDSA', namedCurve } as EcKeyImportParams;
  } else {
    importAlg = algorithm as Algorithm;
  }

  return globalThis.crypto.subtle.importKey(
    'spki',
    spkiDer,
    importAlg,
    false,
    ['verify']
  );
}

/* ------------------------------------------------------------------ */
/*  CRL                                                                */
/* ------------------------------------------------------------------ */

/**
 * Extract CRL Distribution Point URLs from the certificate.
 * Uses @peculiar/x509 to parse the CDP extension (OID 2.5.29.31).
 */
async function extractCrlUrls(cert: X509Certificate): Promise<string[]> {
  try {
    const { X509Certificate: PeculiarX509, CRLDistributionPointsExtension } = await import('@peculiar/x509');
    const pCert = new PeculiarX509(cert.raw);
    const cdpExt = pCert.getExtension(CRLDistributionPointsExtension);
    if (!cdpExt) return [];

    const urls: string[] = [];
    for (const dp of cdpExt.distributionPoints) {
      if (dp.distributionPoint?.fullName) {
        for (const gn of dp.distributionPoint.fullName) {
          // fullName entries are asn1X509.GeneralName objects
          // with uniformResourceIdentifier for URI type (tag 6)
          const uri = (gn as { uniformResourceIdentifier?: string }).uniformResourceIdentifier;
          if (uri) {
            urls.push(uri);
          }
        }
      }
    }
    return urls;
  } catch {
    return [];
  }
}

/**
 * Fetch and verify a CRL, then check if the certificate is listed as revoked.
 */
async function checkCRL(
  cert: X509Certificate,
  issuer: X509Certificate,
  signedAtDate: Date,
  crlUrl: string,
  fetchOpts: SafeFetchOpts
): Promise<void> {
  // reflect-metadata must be imported before @peculiar/x509
  await import('reflect-metadata');
  const { X509Crl, X509Certificate: PeculiarX509 } = await import('@peculiar/x509');

  // Fetch the CRL (max 10 MB)
  const crlBytes = await safeFetch(crlUrl, {
    ...fetchOpts,
    maxBytes: 10 * 1024 * 1024,
  });

  // Parse CRL
  const crl = new X509Crl(new Uint8Array(crlBytes));

  // Verify CRL signature against issuer
  // X509CrlVerifyParams accepts CryptoKey | PublicKey | X509Certificate
  // Pass the issuer as a @peculiar/x509 X509Certificate
  const pIssuer = new PeculiarX509(issuer.raw);
  const valid = await crl.verify({ publicKey: pIssuer });
  if (!valid) {
    throw new Error('CRL signature verification failed');
  }

  // Check CRL is not expired
  const now = new Date();
  if (crl.nextUpdate && crl.nextUpdate < now) {
    throw new Error(
      `CRL expired: nextUpdate was ${crl.nextUpdate.toISOString()}`
    );
  }

  // Check if cert is on the CRL
  const serialHex = cert.serialNumber.replace(/:/g, '');
  const entry = crl.findRevoked(serialHex);

  if (entry) {
    const revokedAt = entry.revocationDate;
    // LTV: if revoked after signing, cert was valid at signing time
    if (revokedAt > signedAtDate) {
      return; // Cert was valid when signature was created
    }
    throw new RevokedError(
      `Certificate was revoked at ${revokedAt.toISOString()}, before signing at ${signedAtDate.toISOString()}`
    );
  }

  // Certificate not on CRL — it is not revoked
}
