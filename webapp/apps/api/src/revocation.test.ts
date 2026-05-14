import 'reflect-metadata';
import { describe, it, expect } from 'vitest';
import { X509Certificate } from 'node:crypto';
import http from 'node:http';
import forge from 'node-forge';
import { checkRevocation } from './revocation.js';

/* ------------------------------------------------------------------ */
/*  Helpers: generate test CA hierarchies with node-forge              */
/* ------------------------------------------------------------------ */

function generateCA(cn: string) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date(Date.now() - 3600_000);
  cert.validity.notAfter = new Date(Date.now() + 10 * 365 * 86400_000);
  cert.setSubject([{ name: 'commonName', value: cn }]);
  cert.setIssuer([{ name: 'commonName', value: cn }]);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
    { name: 'subjectKeyIdentifier' },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return { cert, key: keys.privateKey, publicKey: keys.publicKey, pem: forge.pki.certificateToPem(cert) };
}

function generateLeaf(
  cn: string,
  issuer: { cert: forge.pki.Certificate; key: forge.pki.rsa.PrivateKey }
) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '03';
  cert.validity.notBefore = new Date(Date.now() - 3600_000);
  cert.validity.notAfter = new Date(Date.now() + 365 * 86400_000);
  cert.setSubject([{ name: 'commonName', value: cn }]);
  cert.setIssuer(issuer.cert.subject.attributes);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false, critical: true },
    { name: 'keyUsage', digitalSignature: true, critical: true },
    { name: 'subjectKeyIdentifier' },
    {
      name: 'authorityKeyIdentifier',
      keyIdentifier: true,
    },
  ]);
  cert.sign(issuer.key, forge.md.sha256.create());
  return { cert, key: keys.privateKey, pem: forge.pki.certificateToPem(cert) };
}

/**
 * Build an Authority Information Access extension value (DER) manually.
 * AIA is: SEQUENCE OF AccessDescription
 * AccessDescription ::= SEQUENCE {
 *   accessMethod  OBJECT IDENTIFIER,
 *   accessLocation GeneralName
 * }
 * For OCSP: accessMethod = 1.3.6.1.5.5.7.48.1
 * accessLocation = [6] (uniformResourceIdentifier) IA5String
 */
function buildAIAExtensionValue(ocspUrl: string): string {
  const asn1 = forge.asn1;
  const aiaSeq = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      // accessMethod: id-ad-ocsp (1.3.6.1.5.5.7.48.1)
      asn1.create(
        asn1.Class.UNIVERSAL,
        asn1.Type.OID,
        false,
        asn1.oidToDer('1.3.6.1.5.5.7.48.1').getBytes()
      ),
      // accessLocation: GeneralName [6] uniformResourceIdentifier
      asn1.create(asn1.Class.CONTEXT_SPECIFIC, 6, false, ocspUrl),
    ]),
  ]);
  return asn1.toDer(aiaSeq).getBytes();
}

function generateLeafWithOCSP(
  cn: string,
  issuer: { cert: forge.pki.Certificate; key: forge.pki.rsa.PrivateKey },
  ocspUrl: string
) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '04';
  cert.validity.notBefore = new Date(Date.now() - 3600_000);
  cert.validity.notAfter = new Date(Date.now() + 365 * 86400_000);
  cert.setSubject([{ name: 'commonName', value: cn }]);
  cert.setIssuer(issuer.cert.subject.attributes);
  cert.setExtensions([
    { name: 'keyUsage', digitalSignature: true, critical: true },
    {
      // Authority Information Access OID: 1.3.6.1.5.5.7.1.1
      id: '1.3.6.1.5.5.7.1.1',
      value: buildAIAExtensionValue(ocspUrl),
    },
  ]);
  cert.sign(issuer.key, forge.md.sha256.create());
  return { cert, key: keys.privateKey, pem: forge.pki.certificateToPem(cert) };
}

function generateLeafWithCRL(
  cn: string,
  issuer: { cert: forge.pki.Certificate; key: forge.pki.rsa.PrivateKey },
  crlUrl: string
) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '05';
  cert.validity.notBefore = new Date(Date.now() - 3600_000);
  cert.validity.notAfter = new Date(Date.now() + 365 * 86400_000);
  cert.setSubject([{ name: 'commonName', value: cn }]);
  cert.setIssuer(issuer.cert.subject.attributes);
  cert.setExtensions([
    { name: 'keyUsage', digitalSignature: true, critical: true },
    {
      name: 'cRLDistributionPoints',
      altNames: [{
        type: 6, // URI
        value: crlUrl,
      }],
    },
  ]);
  cert.sign(issuer.key, forge.md.sha256.create());
  return { cert, key: keys.privateKey, pem: forge.pki.certificateToPem(cert) };
}

function toX509(pem: string): X509Certificate {
  return new X509Certificate(pem);
}

/**
 * Import a node-forge RSA private key as a WebCrypto CryptoKey.
 */
async function importForgeKeyAsWebCrypto(
  forgeKey: forge.pki.rsa.PrivateKey
): Promise<CryptoKey> {
  const pkcs8Pem = forge.pki.privateKeyInfoToPem(
    forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(forgeKey))
  );
  const der = pemToDer(pkcs8Pem);
  return globalThis.crypto.subtle.importKey(
    'pkcs8',
    der,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

function pemToDer(pem: string): ArrayBuffer {
  const b64 = pem
    .replace(/-----BEGIN [A-Z ]+-----/g, '')
    .replace(/-----END [A-Z ]+-----/g, '')
    .replace(/\s+/g, '');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/* ------------------------------------------------------------------ */
/*  Tests                                                              */
/* ------------------------------------------------------------------ */

describe('checkRevocation', () => {
  const signedAt = new Date().toISOString();

  it('hard-fail: no OCSP or CRL URLs in certificate', async () => {
    const ca = generateCA('Test Revocation CA - No URLs');
    const leaf = generateLeaf('Leaf No URLs', ca);

    await expect(
      checkRevocation(
        toX509(leaf.pem),
        toX509(ca.pem),
        signedAt,
        { allowLocalhost: true }
      )
    ).rejects.toThrow(/hard-fail/i);
  });

  it('hard-fail: OCSP unreachable, no CRL', async () => {
    const ca = generateCA('Test Revocation CA - OCSP Unreachable');
    const leaf = generateLeafWithOCSP(
      'Leaf OCSP Unreachable',
      ca,
      'http://127.0.0.1:19999/ocsp'
    );

    await expect(
      checkRevocation(
        toX509(leaf.pem),
        toX509(ca.pem),
        signedAt,
        { allowLocalhost: true, timeoutMs: 2000 }
      )
    ).rejects.toThrow(/hard-fail/i);
  });

  it('hard-fail: CRL URL unreachable, no OCSP', async () => {
    const ca = generateCA('Test Revocation CA - CRL Unreachable');
    const leaf = generateLeafWithCRL(
      'Leaf CRL Unreachable',
      ca,
      'http://127.0.0.1:19998/crl.der'
    );

    await expect(
      checkRevocation(
        toX509(leaf.pem),
        toX509(ca.pem),
        signedAt,
        { allowLocalhost: true, timeoutMs: 2000 }
      )
    ).rejects.toThrow(/hard-fail/i);
  });

  it('hard-fail: OCSP returns HTTP error, no CRL', async () => {
    const server = http.createServer((_, res) => {
      res.writeHead(500);
      res.end('Internal Server Error');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as { port: number }).port;

    try {
      const ca = generateCA('Test Revocation CA - OCSP 500');
      const leaf = generateLeafWithOCSP(
        'Leaf OCSP 500',
        ca,
        `http://127.0.0.1:${port}/ocsp`
      );

      await expect(
        checkRevocation(
          toX509(leaf.pem),
          toX509(ca.pem),
          signedAt,
          { allowLocalhost: true, timeoutMs: 5000 }
        )
      ).rejects.toThrow(/hard-fail/i);
    } finally {
      server.close();
    }
  });

  it('hard-fail: OCSP returns garbage data, no CRL', async () => {
    const server = http.createServer((_, res) => {
      res.writeHead(200, { 'Content-Type': 'application/ocsp-response' });
      res.end(Buffer.from('this is not a valid OCSP response'));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as { port: number }).port;

    try {
      const ca = generateCA('Test Revocation CA - OCSP Garbage');
      const leaf = generateLeafWithOCSP(
        'Leaf OCSP Garbage',
        ca,
        `http://127.0.0.1:${port}/ocsp`
      );

      await expect(
        checkRevocation(
          toX509(leaf.pem),
          toX509(ca.pem),
          signedAt,
          { allowLocalhost: true, timeoutMs: 5000 }
        )
      ).rejects.toThrow(/hard-fail/i);
    } finally {
      server.close();
    }
  });

  it('CRL: certificate not on CRL passes', async () => {
    const ca = generateCA('Test Revocation CA - CRL Pass');

    const { X509CrlGenerator } = await import('@peculiar/x509');

    const signingKey = await importForgeKeyAsWebCrypto(ca.key);

    const crl = await X509CrlGenerator.create({
      issuer: toX509(ca.pem).subject,
      thisUpdate: new Date(),
      nextUpdate: new Date(Date.now() + 365 * 86400_000),
      entries: [],
      signingAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      signingKey,
    });

    const crlDer = Buffer.from(crl.rawData);

    const server = http.createServer((_, res) => {
      res.writeHead(200, { 'Content-Type': 'application/pkix-crl' });
      res.end(crlDer);
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as { port: number }).port;

    try {
      const leaf = generateLeafWithCRL(
        'Leaf CRL Pass',
        ca,
        `http://127.0.0.1:${port}/crl.der`
      );

      await checkRevocation(
        toX509(leaf.pem),
        toX509(ca.pem),
        signedAt,
        { allowLocalhost: true, timeoutMs: 5000 }
      );
    } finally {
      server.close();
    }
  });

  it('CRL: certificate revoked before signing throws RevokedError', async () => {
    const ca = generateCA('Test Revocation CA - CRL Revoked Before');

    const { X509CrlGenerator } = await import('@peculiar/x509');

    const signingKey = await importForgeKeyAsWebCrypto(ca.key);

    // Certificate was revoked 1 hour ago
    const revokedAt = new Date(Date.now() - 3600_000);
    // signedAt is now — cert was revoked before signing
    const sigTime = new Date().toISOString();

    const crl = await X509CrlGenerator.create({
      issuer: toX509(ca.pem).subject,
      thisUpdate: new Date(),
      nextUpdate: new Date(Date.now() + 365 * 86400_000),
      entries: [
        { serialNumber: '05', revocationDate: revokedAt },
      ],
      signingAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      signingKey,
    });

    const crlDer = Buffer.from(crl.rawData);

    const server = http.createServer((_, res) => {
      res.writeHead(200, { 'Content-Type': 'application/pkix-crl' });
      res.end(crlDer);
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as { port: number }).port;

    try {
      const leaf = generateLeafWithCRL(
        'Leaf CRL Revoked Before',
        ca,
        `http://127.0.0.1:${port}/crl.der`
      );

      await expect(
        checkRevocation(
          toX509(leaf.pem),
          toX509(ca.pem),
          sigTime,
          { allowLocalhost: true, timeoutMs: 5000 }
        )
      ).rejects.toThrow(/revoked/i);
    } finally {
      server.close();
    }
  });

  it('CRL: LTV — certificate revoked after signing passes', async () => {
    const ca = generateCA('Test Revocation CA - CRL LTV');

    const { X509CrlGenerator } = await import('@peculiar/x509');

    const signingKey = await importForgeKeyAsWebCrypto(ca.key);

    // Signature was created 2 hours ago
    const sigTime = new Date(Date.now() - 2 * 3600_000).toISOString();
    // Certificate was revoked 30 minutes ago (AFTER signing)
    const revokedAt = new Date(Date.now() - 30 * 60_000);

    const crl = await X509CrlGenerator.create({
      issuer: toX509(ca.pem).subject,
      thisUpdate: new Date(),
      nextUpdate: new Date(Date.now() + 365 * 86400_000),
      entries: [
        { serialNumber: '05', revocationDate: revokedAt },
      ],
      signingAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      signingKey,
    });

    const crlDer = Buffer.from(crl.rawData);

    const server = http.createServer((_, res) => {
      res.writeHead(200, { 'Content-Type': 'application/pkix-crl' });
      res.end(crlDer);
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as { port: number }).port;

    try {
      const leaf = generateLeafWithCRL(
        'Leaf CRL LTV',
        ca,
        `http://127.0.0.1:${port}/crl.der`
      );

      // Should pass because cert was revoked AFTER signing
      await checkRevocation(
        toX509(leaf.pem),
        toX509(ca.pem),
        sigTime,
        { allowLocalhost: true, timeoutMs: 5000 }
      );
    } finally {
      server.close();
    }
  });
});
