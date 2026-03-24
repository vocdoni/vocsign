import { z } from 'zod';

const urlField = z.string().trim().url();

// Base64-encoded SHA-256 hash: 32 bytes → 44 base64 chars (with =) or 43 (without padding).
const base64SHA256 = z.string().trim().regex(/^[A-Za-z0-9+/]{42,43}[A-Za-z0-9+/=]{1,2}$/, 'must be a base64-encoded SHA-256 hash').refine(
  (val) => {
    try { return Buffer.from(val, 'base64').length === 32; }
    catch { return false; }
  },
  { message: 'must decode to exactly 32 bytes (SHA-256)' }
);

export const createProposalSchema = z.object({
  targetSignatures: z.number().int().min(0).max(10_000_000).default(0),
  expiresAt: z.string().trim().datetime({ offset: true }).optional(),
  proposal: z.object({
    title: z.string().trim().min(1).max(500),
    promoter: z.string().trim().min(1).max(500),
    jurisdiction: z.string().trim().min(1).max(200),
    summary: z.string().trim().min(1).max(10_000),
    legalStatement: z.string().trim().min(1).max(10_000),
    fullTextURL: urlField,
    fullTextSHA256: base64SHA256
  })
});

export const signResponseSchema = z.object({
  version: z.string().trim().min(1).max(10),
  requestId: z.string().trim().min(1).max(200),
  nonce: z.string().trim().min(1).max(200),
  signedAt: z.string().trim().datetime({ offset: true }),
  payloadCanonicalSha256: base64SHA256,
  signatureFormat: z.string().trim().min(1).max(50),
  signatureDerBase64: z.string().trim().min(1).max(100_000),   // ~75 KB DER max
  signerCertPem: z.string().trim().min(1).max(20_000),         // ~15 KB PEM max
  chainPem: z.array(z.string().trim().max(20_000)).max(10).nullable().optional(),
  signerXmlBase64: z.string().trim().min(1).max(50_000),       // ~37 KB XML max
  timestampTokenBase64: z.string().trim().max(50_000).nullable().optional(),
  client: z
    .object({
      app: z.string().trim().min(1),
      version: z.string().trim().min(1),
      os: z.string().trim().min(1)
    })
    .nullable()
    .optional()
});
