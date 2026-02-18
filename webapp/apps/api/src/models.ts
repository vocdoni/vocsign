import mongoose, { Schema, type InferSchemaType } from 'mongoose';

const proposalSchema = new Schema(
  {
    requestId: { type: String, required: true, unique: true, index: true },
    targetSignatures: { type: Number, required: true, min: 0, default: 0 },
    signaturesCount: { type: Number, required: true, min: 0, default: 0 },
    manifest: { type: Schema.Types.Mixed, required: true }
  },
  { timestamps: true }
);

const signatureSchema = new Schema(
  {
    requestId: { type: String, required: true, index: true },
    signerId: { type: String, required: true },
    signerName: { type: String, required: true },
    signatureDerBase64: { type: String, required: true },
    signerXmlBase64: { type: String, required: true },
    signedXml: { type: String, required: true },
    signerCertPem: { type: String, required: true },
    chainPem: { type: [String], default: [] },
    signedAt: { type: String, required: true },
    payloadCanonicalSha256: { type: String, required: true },
    signatureFormat: { type: String, required: true },
    client: {
      app: { type: String, default: '' },
      version: { type: String, default: '' },
      os: { type: String, default: '' }
    }
  },
  { timestamps: true }
);

signatureSchema.index({ requestId: 1, signerId: 1 }, { unique: true });

export const ProposalModel = mongoose.model('Proposal', proposalSchema);
export const SignatureModel = mongoose.model('Signature', signatureSchema);

export type ProposalDoc = InferSchemaType<typeof proposalSchema>;
export type SignatureDoc = InferSchemaType<typeof signatureSchema>;
