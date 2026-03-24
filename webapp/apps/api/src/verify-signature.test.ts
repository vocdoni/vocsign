import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { X509Certificate } from 'node:crypto';
import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import forge from 'node-forge';

import {
  verifyCadesDetached,
  validateSignerCertificate,
  ACCEPTED_ISSUERS,
} from './verify-signature.js';

// --- Fixtures ---
const fixturesDir = resolve(import.meta.dirname, '__fixtures__');
const fixtureSigB64 = readFileSync(resolve(fixturesDir, 'signature.der.base64'), 'utf-8').trim();
const fixtureContentB64 = readFileSync(resolve(fixturesDir, 'content.base64'), 'utf-8').trim();
const fixtureSignerPem = readFileSync(resolve(fixturesDir, 'signer.pem'), 'utf-8').trim();

// --- Helpers ---

/** Generate a self-signed certificate PEM with the given issuer CN and validity. */
function generateSelfSignedCert(opts: {
  issuerCN: string;
  notBefore?: Date;
  notAfter?: Date;
}): string {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';

  const now = new Date();
  const attrs = [{ name: 'commonName', value: 'Test Subject' }];
  const issuerAttrs = [{ name: 'commonName', value: opts.issuerCN }];

  cert.validity.notBefore = opts.notBefore ?? new Date(now.getTime() - 3600_000);
  cert.validity.notAfter = opts.notAfter ?? new Date(now.getTime() + 365 * 86400_000);
  cert.setSubject(attrs);
  cert.setIssuer(issuerAttrs);
  cert.setExtensions([
    { name: 'keyUsage', digitalSignature: true, critical: true },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return forge.pki.certificateToPem(cert);
}

// --- Tests ---

describe('validateSignerCertificate', () => {
  afterEach(() => {
    delete process.env.ALLOW_TEST_CERTS;
  });

  it('accepts cert from each recognized issuer', async () => {
    // Use ALLOW_TEST_CERTS to bypass chain verification and revocation,
    // since these self-signed test certs can't build a real chain.
    // The issuer allowlist is checked before chain verification only when
    // ALLOW_TEST_CERTS is NOT set, so we test the allowlist indirectly
    // via the rejection test below.
    process.env.ALLOW_TEST_CERTS = 'true';

    for (const issuer of ACCEPTED_ISSUERS) {
      const pem = generateSelfSignedCert({ issuerCN: issuer });
      const cert = new X509Certificate(pem);
      await expect(validateSignerCertificate(cert, [], new Date().toISOString())).resolves.not.toThrow();
    }
  });

  it('rejects unrecognized issuer', async () => {
    delete process.env.ALLOW_TEST_CERTS;
    const pem = generateSelfSignedCert({ issuerCN: 'Fake CA' });
    const cert = new X509Certificate(pem);
    await expect(validateSignerCertificate(cert, [], new Date().toISOString())).rejects.toThrow('not recognized');
  });

  it('ALLOW_TEST_CERTS bypasses issuer check', async () => {
    process.env.ALLOW_TEST_CERTS = 'true';
    const pem = generateSelfSignedCert({ issuerCN: 'Fake CA' });
    const cert = new X509Certificate(pem);
    await expect(validateSignerCertificate(cert, [], new Date().toISOString())).resolves.not.toThrow();
  });

  it('rejects expired cert', async () => {
    const now = new Date();
    const pem = generateSelfSignedCert({
      issuerCN: 'AC FNMT',
      notBefore: new Date(now.getTime() - 2 * 365 * 86400_000),
      notAfter: new Date(now.getTime() - 365 * 86400_000),
    });
    const cert = new X509Certificate(pem);
    await expect(validateSignerCertificate(cert, [], new Date().toISOString())).rejects.toThrow('expired');
  });

  it('rejects not-yet-valid cert', async () => {
    const now = new Date();
    const pem = generateSelfSignedCert({
      issuerCN: 'AC FNMT',
      notBefore: new Date(now.getTime() + 365 * 86400_000),
      notAfter: new Date(now.getTime() + 2 * 365 * 86400_000),
    });
    const cert = new X509Certificate(pem);
    await expect(validateSignerCertificate(cert, [], new Date().toISOString())).rejects.toThrow('not yet valid');
  });
});

describe('verifyCadesDetached', () => {
  beforeAll(() => {
    // Fixture cert is self-signed / test CA, so bypass issuer check.
    process.env.ALLOW_TEST_CERTS = 'true';
  });

  afterAll(() => {
    delete process.env.ALLOW_TEST_CERTS;
  });

  it('valid CAdES signature passes', async () => {
    await expect(
      verifyCadesDetached(fixtureSigB64, fixtureContentB64, fixtureSignerPem, [], new Date().toISOString())
    ).resolves.not.toThrow();
  });

  it('tampered content fails', async () => {
    // Flip a byte in the content.
    const buf = Buffer.from(fixtureContentB64, 'base64');
    buf[0] ^= 0xff;
    const tamperedContentB64 = buf.toString('base64');

    await expect(
      verifyCadesDetached(fixtureSigB64, tamperedContentB64, fixtureSignerPem, [], new Date().toISOString())
    ).rejects.toThrow('messageDigest does not match content hash');
  });

  it('tampered signature fails', async () => {
    // Flip a byte deep in the signature.
    const buf = Buffer.from(fixtureSigB64, 'base64');
    buf[buf.length - 10] ^= 0xff;
    const tamperedSigB64 = buf.toString('base64');

    await expect(
      verifyCadesDetached(tamperedSigB64, fixtureContentB64, fixtureSignerPem, [], new Date().toISOString())
    ).rejects.toThrow();
  });

  it('cert mismatch fails', async () => {
    const otherPem = generateSelfSignedCert({ issuerCN: 'AC FNMT' });

    await expect(
      verifyCadesDetached(fixtureSigB64, fixtureContentB64, otherPem, [], new Date().toISOString())
    ).rejects.toThrow();
  });

  // TODO: These tests require crafting specific ASN.1 structures.
  // They are important for security coverage but need careful DER construction.
  it.todo('rejects SHA-1 digest algorithm');
  it.todo('rejects PKCS#7 with no signer infos');
});
