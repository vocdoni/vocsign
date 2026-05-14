import { describe, it, expect } from 'vitest';
import { loadTrustStore, type TrustStore } from './ca-trust.js';

describe('loadTrustStore', () => {
  let store: TrustStore;

  it('loads certificates from ca-certs directory', () => {
    store = loadTrustStore();
    expect(store.roots.length).toBeGreaterThanOrEqual(5);
  });

  it('roots are self-signed (subject === issuer)', () => {
    store = loadTrustStore();
    for (const root of store.roots) {
      expect(root.subject).toBe(root.issuer);
    }
  });

  it('intermediates have different subject and issuer', () => {
    store = loadTrustStore();
    for (const intermediate of store.intermediates) {
      expect(intermediate.subject).not.toBe(intermediate.issuer);
    }
  });

  it('all certificates are currently valid (not expired)', () => {
    store = loadTrustStore();
    const now = new Date();
    for (const cert of [...store.roots, ...store.intermediates]) {
      expect(new Date(cert.validFrom) <= now).toBe(true);
      expect(new Date(cert.validTo) >= now).toBe(true);
    }
  });
});
