import { X509Certificate } from 'node:crypto';

export interface CertIdentity {
  signerId: string;
  signerName: string;
}

/**
 * Extracts the signer identity (DNI/NIE/CIF and name) from the certificate's
 * Subject DN.
 *
 * Expected subject fields:
 *   serialNumber=IDCES-12345678A  (or IDESP- prefix)
 *   GN=JOAN
 *   SN=GARCIA LOPEZ
 */
export function extractCertIdentity(certPem: string): CertIdentity {
  const cert = new X509Certificate(certPem);
  const subject = cert.subject;

  // Parse subject fields. The subject string uses \n as delimiter between
  // RDN entries, e.g. "CN=GARCIA LOPEZ JOAN\nserialNumber=IDCES-12345678A\n..."
  const fields = new Map<string, string>();
  for (const line of subject.split('\n')) {
    const eqIdx = line.indexOf('=');
    if (eqIdx === -1) continue;
    const key = line.slice(0, eqIdx).trim();
    const value = line.slice(eqIdx + 1).trim();
    fields.set(key, value);
  }

  // Extract signerId from serialNumber field.
  const serialNumber = fields.get('serialNumber') ?? '';
  // Strip IDCES- or IDESP- prefix, then extract DNI/NIE/CIF pattern.
  const stripped = serialNumber.replace(/^IDC?ES-/i, '').replace(/^IDESP-/i, '');
  // DNI: 8 digits + letter, NIE: X/Y/Z + 7 digits + letter, CIF: letter + 8 digits
  const idMatch = stripped.match(/^([0-9]{8}[A-Z]|[XYZ][0-9]{7}[A-Z]|[A-Z][0-9]{8})$/i);
  const signerId = idMatch ? idMatch[1].toUpperCase() : stripped.toUpperCase();

  // Extract name from GN (given name) and SN (surname) fields.
  const givenName = fields.get('GN') ?? '';
  const surname = fields.get('SN') ?? '';
  const signerName = [givenName, surname].filter(Boolean).join(' ').trim();

  return { signerId, signerName };
}
