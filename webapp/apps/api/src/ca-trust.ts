import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { X509Certificate } from 'node:crypto';

export interface TrustStore {
  roots: X509Certificate[];
  intermediates: X509Certificate[];
}

const CA_CERTS_DIR = resolve(
  fileURLToPath(import.meta.url),
  '..',
  'ca-certs'
);

/**
 * Load all PEM files from the ca-certs directory and classify them
 * as roots (self-signed) or intermediates.
 */
export function loadTrustStore(dir: string = CA_CERTS_DIR): TrustStore {
  const roots: X509Certificate[] = [];
  const intermediates: X509Certificate[] = [];

  const files = readdirSync(dir).filter((f) => f.endsWith('.pem'));
  if (files.length === 0) {
    throw new Error(`No PEM files found in ${dir}`);
  }

  for (const file of files) {
    const pem = readFileSync(join(dir, file), 'utf-8');
    // Split concatenated PEMs
    const certPems = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
    if (!certPems) continue;

    for (const certPem of certPems) {
      const cert = new X509Certificate(certPem);
      if (cert.subject === cert.issuer) {
        roots.push(cert);
      } else {
        intermediates.push(cert);
      }
    }
  }

  if (roots.length === 0) {
    throw new Error('No root CA certificates found in trust store');
  }

  return { roots, intermediates };
}

/** Singleton trust store instance, loaded once. */
let _store: TrustStore | null = null;

export function getTrustStore(): TrustStore {
  if (!_store) {
    _store = loadTrustStore();
  }
  return _store;
}
