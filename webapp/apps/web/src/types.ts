export interface SignRequestManifest {
  version: string;
  requestId: string;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  proposal: {
    title: string;
    promoter: string;
    jurisdiction: string;
    summary: string;
    legalStatement: string;
    fullText: {
      url: string;
      sha256: string;
    };
  };
  callback: {
    url: string;
    method: string;
  };
  organizer: {
    kid: string;
    jwkSetUrl: string;
  };
  organizerSignature?: {
    format?: string;
    value?: string;
  };
  policy?: {
    mode?: string;
    oid?: string;
    hashAlg?: string;
    hash?: string;
    uri?: string;
  };
}

export interface ProposalListItem {
  requestId: string;
  title: string;
  promoter: string;
  jurisdiction: string;
  summary: string;
  createdAt: string;
  targetSignatures: number;
  signaturesCount: number;
  signingURL: string;
}

export interface ProposalDetails {
  requestId: string;
  targetSignatures: number;
  signaturesCount: number;
  reachedTarget: boolean;
  signingURL: string;
  manifest: SignRequestManifest;
}

export interface CreateProposalInput {
  targetSignatures: number;
  expiresAt?: string;
  proposal: {
    title: string;
    promoter: string;
    jurisdiction: string;
    summary: string;
    legalStatement: string;
    fullTextURL: string;
  };
}
