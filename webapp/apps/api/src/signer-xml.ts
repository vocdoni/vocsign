import { XMLParser } from 'fast-xml-parser';

const parser = new XMLParser({
  ignoreAttributes: false,
  trimValues: true
});

export interface ParsedSigner {
  signerId: string;
  signerName: string;
  signedXml: string;
}

function text(value: unknown): string {
  if (typeof value === 'string') {
    return value.trim();
  }
  return '';
}

export function parseSignerFromBase64(xmlBase64: string): ParsedSigner {
  const xml = Buffer.from(xmlBase64, 'base64').toString('utf8');
  const parsed = parser.parse(xml);

  const root = parsed?.SignaturaILP;
  const signer = root?.Signant ?? {};

  const nameParts = [text(signer.Nom), text(signer.Cognom1), text(signer.Cognom2)].filter(Boolean);
  const signerName = nameParts.join(' ').trim();
  const signerId = text(signer.NumeroIdentificador).toUpperCase();

  if (!signerName || !signerId) {
    throw new Error('Could not extract signer name and ID from signer XML');
  }

  return {
    signerId,
    signerName,
    signedXml: xml
  };
}
