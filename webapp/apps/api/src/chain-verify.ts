import { X509Certificate } from 'node:crypto';
import type { TrustStore } from './ca-trust.js';

const MAX_CHAIN_DEPTH = 5;

export async function verifyChain(
  leaf: X509Certificate,
  chainPems: string[],
  store: TrustStore
): Promise<X509Certificate> {
  const clientCerts: X509Certificate[] = chainPems.map((pem) => new X509Certificate(pem));
  const candidates = [...clientCerts, ...store.intermediates, ...store.roots];

  let current = leaf;
  let directIssuer: X509Certificate | null = null;

  for (let depth = 0; depth < MAX_CHAIN_DEPTH; depth++) {
    if (isTrustedRoot(current, store)) {
      if (directIssuer === null) {
        throw new Error('Leaf certificate is a self-signed root');
      }
      return directIssuer;
    }

    const issuer = findAndVerifyIssuer(current, candidates);
    if (!issuer) {
      throw new Error(
        `Cannot build certificate chain: no valid issuer found for "${current.subject}"`
      );
    }

    if (depth === 0) {
      directIssuer = issuer;
    }

    if (isTrustedRoot(issuer, store)) {
      return directIssuer!;
    }

    if (!issuer.ca) {
      throw new Error(
        `Intermediate certificate "${issuer.subject}" does not have CA:true basic constraint`
      );
    }

    current = issuer;
  }

  throw new Error(`Certificate chain exceeds maximum depth of ${MAX_CHAIN_DEPTH}`);
}

function isTrustedRoot(cert: X509Certificate, store: TrustStore): boolean {
  return store.roots.some((root) => root.fingerprint256 === cert.fingerprint256);
}

function findAndVerifyIssuer(
  cert: X509Certificate,
  candidates: X509Certificate[]
): X509Certificate | null {
  for (const candidate of candidates) {
    if (cert.issuer !== candidate.subject) continue;
    if (cert.verify(candidate.publicKey)) {
      const now = new Date();
      if (now < new Date(candidate.validFrom) || now > new Date(candidate.validTo)) {
        throw new Error(
          `Issuer certificate "${candidate.subject}" has expired (validTo: ${candidate.validTo})`
        );
      }
      return candidate;
    }
  }
  return null;
}
