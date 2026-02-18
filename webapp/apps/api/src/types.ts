export interface SignPolicy {
  mode: string;
  oid?: string;
  hashAlg?: string;
  hash?: string;
  uri?: string;
}

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
    format: string;
    value: string;
  };
  policy?: SignPolicy;
}

export interface SignResponse {
  version: string;
  requestId: string;
  nonce: string;
  signedAt: string;
  payloadCanonicalSha256: string;
  signatureFormat: string;
  signatureDerBase64: string;
  signerCertPem: string;
  chainPem?: string[];
  signerXmlBase64?: string;
  client?: {
    app: string;
    version: string;
    os: string;
  };
}
