import { z } from 'zod';

const urlField = z.string().trim().url();

export const createProposalSchema = z.object({
  targetSignatures: z.number().int().min(0).default(0),
  expiresAt: z.string().trim().datetime({ offset: true }).optional(),
  proposal: z.object({
    title: z.string().trim().min(1),
    promoter: z.string().trim().min(1),
    jurisdiction: z.string().trim().min(1),
    summary: z.string().trim().min(1),
    legalStatement: z.string().trim().min(1),
    fullTextURL: urlField
  })
});

export const signResponseSchema = z.object({
  version: z.string().trim().min(1),
  requestId: z.string().trim().min(1),
  nonce: z.string().trim().min(1),
  signedAt: z.string().trim().datetime({ offset: true }),
  payloadCanonicalSha256: z.string().trim().min(1),
  signatureFormat: z.string().trim().min(1),
  signatureDerBase64: z.string().trim().min(1),
  signerCertPem: z.string().trim().min(1),
  chainPem: z.array(z.string().trim()).nullable().optional(),
  signerXmlBase64: z.string().trim().min(1),
  client: z
    .object({
      app: z.string().trim().min(1),
      version: z.string().trim().min(1),
      os: z.string().trim().min(1)
    })
    .nullable()
    .optional()
});
