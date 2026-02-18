import path from 'node:path';
import {
  createECDH,
  createHash,
  createPrivateKey,
  createSign,
  randomBytes,
  randomUUID,
  type KeyObject
} from 'node:crypto';
import { fileURLToPath } from 'node:url';

import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';
import mongoose from 'mongoose';

import { ProposalModel, SignatureModel } from './models.js';
import { parseSignerFromBase64 } from './signer-xml.js';
import { createProposalSchema, signResponseSchema } from './validation.js';

dotenv.config();

const app = express();
const port = Number(process.env.PORT ?? 8080);
const mongoUri = process.env.MONGODB_URI ?? 'mongodb://localhost:27017/vocsign_portal';
const publicBaseURL = (process.env.PORTAL_DOMAIN_URL ?? process.env.PUBLIC_BASE_URL ?? `http://localhost:${port}`).replace(
  /\/$/,
  ''
);
const organizerKID = process.env.ORGANIZER_KID ?? 'vocsign-portal-organizer';
const organizerJWKSetURL = process.env.ORGANIZER_JWKS_URL ?? `${publicBaseURL}/jwks.json`;
const organizerKeyHex = process.env.ORGANIZER_PRIVATE_KEY_HEX ?? '';
const policyOID = process.env.POLICY_OID ?? '1.3.6.1.4.1.47443.8.1.1';
const policyURI = process.env.POLICY_URI ?? `${publicBaseURL}/policy.pdf`;
const defaultValidityDays = Number(process.env.DEFAULT_PROPOSAL_VALIDITY_DAYS ?? 365);

type JWKPublicEC = {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
};

type OrganizerSigner = {
  privateKey: KeyObject;
  jwk: JWKPublicEC;
};

function isDuplicateKeyError(err: unknown): boolean {
  return typeof err === 'object' && err !== null && 'code' in err && (err as { code?: number }).code === 11000;
}

function privateHexToSigner(hexKey: string): OrganizerSigner {
  const normalized = hexKey.trim().toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    throw new Error('ORGANIZER_PRIVATE_KEY_HEX must be exactly 64 hex chars (32 bytes)');
  }

  const privateScalar = Buffer.from(normalized, 'hex');
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(privateScalar)
  const pubUncompressed = ecdh.getPublicKey(undefined, 'uncompressed');
  if (pubUncompressed.length !== 65 || pubUncompressed[0] !== 0x04) {
    throw new Error('failed to derive EC public key from ORGANIZER_PRIVATE_KEY_HEX');
  }

  const jwkPrivate = {
    kty: 'EC',
    crv: 'P-256',
    x: toBase64URL(pubUncompressed.subarray(1, 33)),
    y: toBase64URL(pubUncompressed.subarray(33, 65)),
    d: toBase64URL(privateScalar)
  } as const;

  const privateKey = createPrivateKey({ key: jwkPrivate, format: 'jwk' });
  return {
    privateKey,
    jwk: {
      kty: 'EC',
      crv: 'P-256',
      x: jwkPrivate.x,
      y: jwkPrivate.y
    }
  };
}

function loadOrganizerSigner(): OrganizerSigner {
  const hex = organizerKeyHex.trim();
  if (hex == '') {
    throw new Error('missing ORGANIZER_PRIVATE_KEY_HEX');
  }
  return privateHexToSigner(hex);
}

const organizerSigner = loadOrganizerSigner();

function slugify(input: string): string {
  return input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);
}

function buildRequestID(title: string): string {
  const base = slugify(title) || 'proposal';
  return `${base}-${randomUUID().slice(0, 8)}`;
}

function sha256Base64(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('base64');
}

function randomNonceBase64(): string {
  return randomBytes(16).toString('base64');
}

function toBase64URL(value: Buffer | string): string {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8');
  return bytes
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function signJWS(payloadJSON: string): string {
  const header = { alg: 'ES256', typ: 'JWS' };
  const headerB64 = toBase64URL(JSON.stringify(header));
  const payloadB64 = toBase64URL(payloadJSON);
  const signingInput = `${headerB64}.${payloadB64}`;

  const signer = createSign('SHA256');
  signer.update(signingInput);
  signer.end();
  const signature = signer.sign({ key: organizerSigner.privateKey, dsaEncoding: 'ieee-p1363' });

  return `${signingInput}.${toBase64URL(signature)}`;
}

app.use(cors());
app.use(express.json({ limit: '2mb' }));

app.get('/api/health', (_req, res) => {
  res.json({ ok: true });
});

app.get('/jwks.json', (_req, res) => {
  res.json({
    keys: [
      {
        kid: organizerKID,
        kty: 'EC',
        crv: 'P-256',
        alg: 'ES256',
        use: 'sig',
        x: organizerSigner.jwk.x,
        y: organizerSigner.jwk.y
      }
    ]
  });
});

app.get('/api/proposals', async (req, res) => {
  const query = ProposalModel.find({}, { _id: 0, __v: 0 }).limit(100);
  if (req.query.sort === 'signatures') {
    query.sort({ signaturesCount: -1, createdAt: -1 });
  } else {
    query.sort({ createdAt: -1 });
  }
  const proposals = await query.lean();

  res.json(
    proposals.map((proposal) => ({
      requestId: proposal.requestId,
      title: proposal.manifest?.proposal?.title ?? proposal.requestId,
      promoter: proposal.manifest?.proposal?.promoter ?? '',
      jurisdiction: proposal.manifest?.proposal?.jurisdiction ?? '',
      summary: proposal.manifest?.proposal?.summary ?? '',
      createdAt: proposal.createdAt,
      targetSignatures: proposal.targetSignatures,
      signaturesCount: proposal.signaturesCount,
      signingURL: `${publicBaseURL}/request/${proposal.requestId}`
    }))
  );
});

app.post('/api/proposals', async (req, res) => {
  const parsed = createProposalSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid proposal payload', details: parsed.error.flatten() });
  }

  const { targetSignatures, proposal, expiresAt } = parsed.data;
  const requestId = buildRequestID(proposal.title);
  const now = new Date();

  const manifestUnsigned = {
    version: '1.0',
    requestId,
    issuedAt: now.toISOString(),
    expiresAt: expiresAt ?? new Date(now.getTime() + defaultValidityDays * 24 * 60 * 60 * 1000).toISOString(),
    nonce: randomNonceBase64(),
    proposal: {
      title: proposal.title,
      promoter: proposal.promoter,
      jurisdiction: proposal.jurisdiction,
      summary: proposal.summary,
      legalStatement: proposal.legalStatement,
      fullText: {
        url: proposal.fullTextURL,
        sha256: sha256Base64(proposal.fullTextURL)
      }
    },
    callback: {
      url: `${publicBaseURL}/api/callback/${requestId}`,
      method: 'POST'
    },
    organizer: {
      kid: organizerKID,
      jwkSetUrl: organizerJWKSetURL
    },
    policy: {
      mode: 'required',
      oid: policyOID,
      hashAlg: 'sha256',
      hash: sha256Base64(proposal.title + proposal.legalStatement),
      uri: policyURI
    }
  };

  const manifest = {
    ...manifestUnsigned,
    organizerSignature: {
      format: 'JWS',
      value: signJWS(JSON.stringify(manifestUnsigned))
    }
  };

  try {
    const created = await ProposalModel.create({
      requestId,
      targetSignatures,
      signaturesCount: 0,
      manifest
    });

    return res.status(201).json({
      requestId: created.requestId,
      signingURL: `${publicBaseURL}/request/${created.requestId}`,
      callbackURL: created.manifest.callback.url,
      targetSignatures: created.targetSignatures,
      signaturesCount: created.signaturesCount
    });
  } catch (err) {
    if (err instanceof mongoose.Error && (err as { code?: number }).code === 11000) {
      return res.status(409).json({ error: 'A proposal with this requestId already exists' });
    }
    console.error(err);
    return res.status(500).json({ error: 'Could not create proposal' });
  }
});

app.get('/api/proposals/:requestId', async (req, res) => {
  const proposal = await ProposalModel.findOne({ requestId: req.params.requestId }, { _id: 0, __v: 0 }).lean();
  if (!proposal) {
    return res.status(404).json({ error: 'Proposal not found' });
  }

  const reachedTarget = proposal.targetSignatures > 0 && proposal.signaturesCount >= proposal.targetSignatures;

  return res.json({
    requestId: proposal.requestId,
    targetSignatures: proposal.targetSignatures,
    signaturesCount: proposal.signaturesCount,
    reachedTarget,
    signingURL: `${publicBaseURL}/request/${proposal.requestId}`,
    manifest: proposal.manifest
  });
});

app.get('/request/:requestId', async (req, res) => {
  const proposal = await ProposalModel.findOne({ requestId: req.params.requestId }).lean();
  if (!proposal) {
    return res.status(404).json({ error: 'Proposal not found' });
  }
  return res.json(proposal.manifest);
});

app.post('/api/callback/:requestId', async (req, res) => {
  const parsed = signResponseSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      error: 'Invalid sign response payload',
      details: parsed.error.flatten()
    });
  }

  const { requestId } = req.params;
  const signResponse = parsed.data;
  if (requestId !== signResponse.requestId) {
    return res.status(400).json({ error: 'requestId mismatch' });
  }

  const proposal = await ProposalModel.findOne({ requestId }).lean();
  if (!proposal) {
    return res.status(404).json({ error: 'Proposal not found' });
  }

  let signer;
  try {
    signer = parseSignerFromBase64(signResponse.signerXmlBase64);
  } catch (err) {
    return res.status(400).json({ error: err instanceof Error ? err.message : 'Invalid signer XML' });
  }

  // Friendly early check: an ID can sign only once per proposal.
  const alreadySigned = await SignatureModel.exists({ requestId, signerId: signer.signerId });
  if (alreadySigned) {
    return res.status(409).json({ error: 'This ID has already signed this proposal' });
  }

  try {
    await SignatureModel.create({
      requestId,
      signerId: signer.signerId,
      signerName: signer.signerName,
      signatureDerBase64: signResponse.signatureDerBase64,
      signerXmlBase64: signResponse.signerXmlBase64,
      signedXml: signer.signedXml,
      signerCertPem: signResponse.signerCertPem,
      chainPem: signResponse.chainPem ?? [],
      signedAt: signResponse.signedAt,
      payloadCanonicalSha256: signResponse.payloadCanonicalSha256,
      signatureFormat: signResponse.signatureFormat,
      client: {
        app: signResponse.client?.app ?? '',
        version: signResponse.client?.version ?? '',
        os: signResponse.client?.os ?? ''
      }
    });
  } catch (err) {
    // Keep race-safe behavior even if two requests pass the pre-check concurrently.
    if (isDuplicateKeyError(err)) {
      return res.status(409).json({ error: 'This ID has already signed this proposal' });
    }
    console.error(err);
    return res.status(500).json({ error: 'Could not store signature' });
  }

  await ProposalModel.updateOne({ requestId }, { $inc: { signaturesCount: 1 } });

  return res.status(201).json({
    status: 'accepted',
    requestId,
    signaturesCount: proposal.signaturesCount + 1
  });
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const webDist = path.resolve(__dirname, '../../web/dist');
app.use(express.static(webDist));
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/') || req.path.startsWith('/request/') || req.path === '/jwks.json') {
    return next();
  }
  return res.sendFile(path.join(webDist, 'index.html'));
});

async function bootstrap(): Promise<void> {
  await mongoose.connect(mongoUri);
  console.log(`Connected to MongoDB at ${mongoUri}`);
  app.listen(port, () => {
    console.log(`Vocsign portal listening on http://0.0.0.0:${port}`);
  });
}

bootstrap().catch((err) => {
  console.error('Fatal startup error', err);
  process.exit(1);
});
