import { createHash, createVerify, X509Certificate } from 'node:crypto';

import forge from 'node-forge';

import { getTrustStore } from './ca-trust.js';
import { verifyChain } from './chain-verify.js';
import { checkRevocation } from './revocation.js';

// Map OIDs to Node.js hash algorithm names.
// SHA-1 is intentionally excluded — it is broken for collision resistance.
const digestAlgorithms: Record<string, string> = {
  '2.16.840.1.101.3.4.2.1': 'SHA256',
  '2.16.840.1.101.3.4.2.2': 'SHA384',
  '2.16.840.1.101.3.4.2.3': 'SHA512',
};

/**
 * Verifies a CAdES detached PKCS#7 signature.
 *
 * Checks that:
 * 1. The PKCS#7 structure is valid SignedData with at least one signer.
 * 2. The messageDigest authenticated attribute matches the hash of the
 *    original content (the ILP XML), using the digest algorithm declared
 *    in the PKCS#7 structure.
 * 3. The signature over the authenticated attributes is valid using the
 *    signer's certificate.
 * 4. The signer certificate in the PKCS#7 matches the one provided in the
 *    response.
 */
export async function verifyCadesDetached(
  signatureDerBase64: string,
  contentBase64: string,
  signerCertPem: string,
  chainPems: string[],
  signedAt: string
): Promise<void> {
  // 1. Decode inputs.
  const sigDer = Buffer.from(signatureDerBase64, 'base64');
  const content = Buffer.from(contentBase64, 'base64');

  // 2. Parse the PKCS#7 DER structure.
  const asn1 = forge.asn1.fromDer(forge.util.createBuffer(sigDer));
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const msg = forge.pkcs7.messageFromAsn1(asn1) as any;
  const rc = msg.rawCapture;

  if (!rc.signerInfos || rc.signerInfos.length === 0) {
    throw new Error('PKCS#7 contains no signer infos');
  }

  // Determine the digest algorithm from the PKCS#7 structure.
  const digestOid = forge.asn1.derToOid(rc.digestAlgorithm);
  const hashAlg = digestAlgorithms[digestOid];
  if (!hashAlg) {
    throw new Error(`Unsupported digest algorithm OID: ${digestOid}`);
  }

  // 3. Verify messageDigest attribute matches content hash.
  const contentHash = createHash(hashAlg).update(content).digest();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const mdAttr = rc.authenticatedAttributes?.find((a: any) => {
    return forge.asn1.derToOid(a.value[0].value) === forge.pki.oids.messageDigest;
  });
  if (!mdAttr) {
    throw new Error('Missing messageDigest authenticated attribute');
  }
  const mdBytes = Buffer.from(mdAttr.value[1].value[0].value, 'binary');
  if (!contentHash.equals(mdBytes)) {
    throw new Error('messageDigest does not match content hash');
  }

  // 4. Verify the signature over the authenticated attributes.
  //    The authenticated attributes are stored in the SignerInfo ASN.1 as a
  //    CONTEXT_SPECIFIC [0] IMPLICIT SET. For verification, we re-tag them as
  //    a UNIVERSAL SET (the standard PKCS#7 verification procedure).
  const siAsn1 = rc.signerInfos[0];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const authAttrsAsn1 = siAsn1.value.find((v: any) =>
    v.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && v.type === 0
  );
  if (!authAttrsAsn1) {
    throw new Error('No authenticated attributes in SignerInfo');
  }

  const setOfAttrs = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SET,
    true,
    authAttrsAsn1.value
  );
  const attrsDer = Buffer.from(forge.asn1.toDer(setOfAttrs).getBytes(), 'binary');
  const signature = Buffer.from(rc.signature, 'binary');

  const cert = new X509Certificate(signerCertPem);
  const verifier = createVerify(hashAlg);
  verifier.update(attrsDer);
  if (!verifier.verify(cert.publicKey, signature)) {
    throw new Error('Signature verification failed');
  }

  // 5. Verify the provided cert PEM matches the signer in the PKCS#7.
  const providedFingerprint = createHash('sha256').update(cert.raw).digest('hex');
  const p7Certs = msg.certificates;
  if (p7Certs && p7Certs.length > 0) {
    const p7Der = forge.asn1.toDer(forge.pki.certificateToAsn1(p7Certs[0])).getBytes();
    const p7Fingerprint = createHash('sha256')
      .update(Buffer.from(p7Der, 'binary'))
      .digest('hex');
    if (providedFingerprint !== p7Fingerprint) {
      throw new Error('Signer certificate does not match the certificate in the PKCS#7 structure');
    }
  }

  // 6. Validate the signer certificate itself.
  await validateSignerCertificate(cert, chainPems, signedAt);
}

export const ACCEPTED_ISSUERS = [
  'AC FNMT',
  'FNMT-RCM',
  'EC-Ciutadania',
  'EC-idCAT',
  'EC-SectorPublic',
  'EC-AL',
  'Agencia Catalana de Certificacio',
  'Consorci AOC',
  'ACCV',
  'IZENPE',
  'ANF AC',
];

export async function validateSignerCertificate(
  cert: X509Certificate,
  chainPems: string[],
  signedAt: string
): Promise<void> {
  // 6a. Check validity period.
  const now = new Date();
  const validFrom = new Date(cert.validFrom);
  const validTo = new Date(cert.validTo);
  if (now < validFrom) {
    throw new Error(`certificate is not yet valid (validFrom: ${cert.validFrom})`);
  }
  if (now > validTo) {
    throw new Error(`certificate has expired (validTo: ${cert.validTo})`);
  }

  // 6b. Check key usage includes digitalSignature, if the extension is present.
  const keyUsage = cert.keyUsage;
  if (keyUsage !== undefined && !keyUsage.includes('digitalSignature')) {
    throw new Error('certificate key usage does not include digitalSignature');
  }

  // Skip chain verification and revocation in test mode.
  if (process.env.ALLOW_TEST_CERTS === 'true') {
    return;
  }

  // 6c. Issuer allowlist check.
  const issuerLower = cert.issuer.toLowerCase();
  const recognized = ACCEPTED_ISSUERS.some(
    (name) => issuerLower.includes(name.toLowerCase())
  );
  if (!recognized) {
    throw new Error(
      `certificate issuer not recognized as a trusted Spanish CA: ${cert.issuer}`
    );
  }

  // 6d. Chain verification.
  const store = getTrustStore();
  const issuer = await verifyChain(cert, chainPems, store);

  // 6e. Revocation check with LTV.
  await checkRevocation(cert, issuer, signedAt);
}
