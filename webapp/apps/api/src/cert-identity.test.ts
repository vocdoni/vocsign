import { describe, it, expect } from 'vitest';
import forge from 'node-forge';

import { extractCertIdentity } from './cert-identity.js';

/** Build a self-signed PEM cert with specific subject attributes. */
function buildCertWithSubject(attrs: {
  serialNumber?: string;
  givenName?: string;
  surname?: string;
  cn?: string;
}): string {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date(Date.now() + 365 * 86400_000);

  const subject: forge.pki.CertificateField[] = [];
  if (attrs.cn) {
    subject.push({ name: 'commonName', value: attrs.cn });
  }
  if (attrs.serialNumber !== undefined) {
    subject.push({ name: 'serialNumber', value: attrs.serialNumber });
  }
  if (attrs.givenName !== undefined) {
    // OID 2.5.4.42 = GN (givenName)
    subject.push({ name: 'givenName', value: attrs.givenName });
  }
  if (attrs.surname !== undefined) {
    // OID 2.5.4.4 = SN (surname)
    subject.push({ name: 'surname', value: attrs.surname });
  }

  cert.setSubject(subject);
  cert.setIssuer([{ name: 'commonName', value: 'Test CA' }]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return forge.pki.certificateToPem(cert);
}

describe('extractCertIdentity', () => {
  const cases = [
    {
      name: 'FNMT DNI (IDCES prefix)',
      attrs: { serialNumber: 'IDCES-00000000T', givenName: 'JUAN', surname: 'ESPANOL ESPANOL', cn: 'ESPANOL ESPANOL JUAN' },
      wantId: '00000000T',
      wantName: 'JUAN ESPANOL ESPANOL',
    },
    {
      name: 'AOC DNI (IDCES prefix)',
      attrs: { serialNumber: 'IDCES-47824166J', givenName: 'PAU', surname: 'ESCRICH GARCIA', cn: 'PAU ESCRICH GARCIA' },
      wantId: '47824166J',
      wantName: 'PAU ESCRICH GARCIA',
    },
    {
      name: 'ACCV DNI (no prefix)',
      attrs: { serialNumber: '00000000T', givenName: 'MARIA', surname: 'LOPEZ GARCIA', cn: 'MARIA LOPEZ GARCIA' },
      wantId: '00000000T',
      wantName: 'MARIA LOPEZ GARCIA',
    },
    {
      name: 'IZENPE DNI',
      attrs: { serialNumber: 'IDCES-09421399R', givenName: 'JAIME', surname: 'RODRIGO POCH', cn: '09421399R JAIME RODRIGO' },
      wantId: '09421399R',
      wantName: 'JAIME RODRIGO POCH',
    },
    {
      name: 'NIE (IDCES prefix)',
      attrs: { serialNumber: 'IDCES-X1234567A', givenName: 'ANNA', surname: 'SMITH', cn: 'ANNA SMITH' },
      wantId: 'X1234567A',
      wantName: 'ANNA SMITH',
    },
    {
      name: 'CIF representative',
      attrs: { serialNumber: 'IDCES-B75576322', givenName: 'PAU', surname: 'ESCRICH', cn: 'PAU ESCRICH' },
      wantId: 'B75576322',
      wantName: 'PAU ESCRICH',
    },
    {
      name: 'IDESP prefix',
      attrs: { serialNumber: 'IDESP-12345678Z', givenName: 'ALBA', surname: 'TESTER', cn: 'ALBA TESTER' },
      wantId: '12345678Z',
      wantName: 'ALBA TESTER',
    },
    {
      name: 'missing GN and SN',
      attrs: { serialNumber: 'IDCES-12345678Z', cn: 'SOMEONE' },
      wantId: '12345678Z',
      wantName: '',
    },
    {
      name: 'IDES prefix (no C)',
      attrs: { serialNumber: 'IDES-12345678Z', givenName: 'ALBA', surname: 'TESTER', cn: 'ALBA TESTER' },
      wantId: '12345678Z',
      wantName: 'ALBA TESTER',
    },
    {
      name: 'unrecognized serialNumber format',
      attrs: { serialNumber: 'PASSPORT-ABC123', givenName: 'JOHN', surname: 'DOE', cn: 'JOHN DOE' },
      wantId: 'PASSPORT-ABC123',
      wantName: 'JOHN DOE',
    },
  ];

  for (const tc of cases) {
    it(tc.name, () => {
      const pem = buildCertWithSubject(tc.attrs);
      const result = extractCertIdentity(pem);
      expect(result.signerId).toBe(tc.wantId);
      expect(result.signerName).toBe(tc.wantName);
    });
  }
});
