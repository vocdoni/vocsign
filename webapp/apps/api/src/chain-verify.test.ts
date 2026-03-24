import { describe, it, expect } from 'vitest';
import { X509Certificate } from 'node:crypto';
import forge from 'node-forge';
import { verifyChain } from './chain-verify.js';
import type { TrustStore } from './ca-trust.js';

/* ------------------------------------------------------------------ */
/*  Helpers: generate test CA hierarchies in-process using node-forge  */
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
  return { cert, key: keys.privateKey, pem: forge.pki.certificateToPem(cert) };
}

function generateIntermediate(
  cn: string,
  issuer: { cert: forge.pki.Certificate; key: forge.pki.rsa.PrivateKey },
  opts?: { caFlag?: boolean; expired?: boolean }
) {
  const caFlag = opts?.caFlag ?? true;
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '02';
  cert.validity.notBefore = new Date(Date.now() - 3600_000);
  cert.validity.notAfter = opts?.expired
    ? new Date(Date.now() - 1000) // already expired
    : new Date(Date.now() + 10 * 365 * 86400_000);
  cert.setSubject([{ name: 'commonName', value: cn }]);
  cert.setIssuer(issuer.cert.subject.attributes);
  cert.setExtensions([
    { name: 'basicConstraints', cA: caFlag, critical: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
    { name: 'subjectKeyIdentifier' },
    {
      name: 'authorityKeyIdentifier',
      keyIdentifier: true,
    },
  ]);
  cert.sign(issuer.key, forge.md.sha256.create());
  return { cert, key: keys.privateKey, pem: forge.pki.certificateToPem(cert) };
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

/** Convert a forge PEM string to a Node.js X509Certificate */
function toX509(pem: string): X509Certificate {
  return new X509Certificate(pem);
}

/** Build a minimal TrustStore from root and intermediate PEMs */
function makeStore(
  rootPems: string[],
  intermediatePems: string[] = []
): TrustStore {
  return {
    roots: rootPems.map(toX509),
    intermediates: intermediatePems.map(toX509),
  };
}

/* ------------------------------------------------------------------ */
/*  Tests                                                              */
/* ------------------------------------------------------------------ */

describe('verifyChain', () => {
  it('valid root → intermediate → leaf chain (chainPems provided) returns intermediate as issuer', async () => {
    const root = generateCA('Test Root CA');
    const intermediate = generateIntermediate('Test Intermediate CA', root);
    const leaf = generateLeaf('Test Leaf', intermediate);

    const store = makeStore([root.pem]);
    const issuer = await verifyChain(toX509(leaf.pem), [intermediate.pem], store);

    expect(issuer.fingerprint256).toBe(toX509(intermediate.pem).fingerprint256);
  });

  it('intermediate in trust store instead of chainPem still works', async () => {
    const root = generateCA('Test Root CA 2');
    const intermediate = generateIntermediate('Test Intermediate CA 2', root);
    const leaf = generateLeaf('Test Leaf 2', intermediate);

    const store = makeStore([root.pem], [intermediate.pem]);
    const issuer = await verifyChain(toX509(leaf.pem), [], store);

    expect(issuer.fingerprint256).toBe(toX509(intermediate.pem).fingerprint256);
  });

  it('direct root → leaf chain returns root as issuer', async () => {
    const root = generateCA('Test Direct Root CA');
    const leaf = generateLeaf('Test Direct Leaf', root);

    const store = makeStore([root.pem]);
    const issuer = await verifyChain(toX509(leaf.pem), [], store);

    expect(issuer.fingerprint256).toBe(toX509(root.pem).fingerprint256);
  });

  it('leaf signed by unknown CA rejects with "chain" error', async () => {
    const root = generateCA('Known Root CA');
    const unknownCA = generateCA('Unknown Root CA');
    const leaf = generateLeaf('Rogue Leaf', unknownCA);

    const store = makeStore([root.pem]);

    await expect(verifyChain(toX509(leaf.pem), [], store)).rejects.toThrow(
      /chain/i
    );
  });

  it('intermediate without CA:true rejects with "CA" error', async () => {
    const root = generateCA('Test Root CA NoCA');
    const badIntermediate = generateIntermediate('Bad Intermediate', root, {
      caFlag: false,
    });
    const leaf = generateLeaf('Test Leaf NoCA', badIntermediate);

    const store = makeStore([root.pem]);

    await expect(
      verifyChain(toX509(leaf.pem), [badIntermediate.pem], store)
    ).rejects.toThrow(/CA/);
  });

  it('chain exceeds max depth rejects with "depth" error', async () => {
    // Build: root → inter0 → inter1 → inter2 → inter3 → inter4 → leaf
    // That is 6 links from leaf to root, exceeding MAX_CHAIN_DEPTH of 5
    const root = generateCA('Deep Root CA');
    const intermediates: ReturnType<typeof generateIntermediate>[] = [];

    let parent: { cert: forge.pki.Certificate; key: forge.pki.rsa.PrivateKey } = root;
    for (let i = 0; i < 5; i++) {
      const inter = generateIntermediate(`Deep Intermediate ${i}`, parent);
      intermediates.push(inter);
      parent = inter;
    }
    const leaf = generateLeaf('Deep Leaf', parent);

    const store = makeStore([root.pem]);
    const chainPems = intermediates.map((i) => i.pem);

    await expect(
      verifyChain(toX509(leaf.pem), chainPems, store)
    ).rejects.toThrow(/depth/i);
  });

  it('expired intermediate in chain rejects with "expired" error', async () => {
    const root = generateCA('Test Root CA Exp');
    const expiredIntermediate = generateIntermediate(
      'Expired Intermediate',
      root,
      { expired: true }
    );
    const leaf = generateLeaf('Test Leaf Exp', expiredIntermediate);

    const store = makeStore([root.pem]);

    await expect(
      verifyChain(toX509(leaf.pem), [expiredIntermediate.pem], store)
    ).rejects.toThrow(/expired/i);
  });
});
