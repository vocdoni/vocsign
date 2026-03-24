import path from 'node:path';
import {
  createECDH,
  createHash,
  createPrivateKey,
  createSign,
  randomBytes,
  randomUUID,
  timingSafeEqual,
  type KeyObject
} from 'node:crypto';
import { fileURLToPath } from 'node:url';

import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';
import mongoose from 'mongoose';

import { ProposalModel, SignatureModel } from './models.js';
import { parseSignerFromBase64 } from './signer-xml.js';
import { extractCertIdentity } from './cert-identity.js';
import { createProposalSchema, signResponseSchema } from './validation.js';
import { verifyCadesDetached } from './verify-signature.js';

const __apiDir = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__apiDir, '..', '..', '..', '.env') });

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
const releaseBaseURL = process.env.VOCSIGN_RELEASE_BASE_URL ?? 'https://github.com/vocdoni/vocsign/releases/latest';
const organizerApiKey = process.env.ORGANIZER_API_KEY ?? '';

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

app.use((_req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('X-XSS-Protection', '0');
  res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

app.use(cors({
  origin: publicBaseURL,
  methods: ['GET', 'POST'],
}));
app.use(express.json({ limit: '2mb' }));

// ---------------------------------------------------------------------------
// In-memory sliding-window rate limiter (per IP).
// ---------------------------------------------------------------------------
type RateBucket = { timestamps: number[] };
const rateBuckets = new Map<string, RateBucket>();

// Purge stale entries every 5 minutes.
setInterval(() => {
  const cutoff = Date.now() - 120_000;
  for (const [key, bucket] of rateBuckets) {
    bucket.timestamps = bucket.timestamps.filter((t) => t > cutoff);
    if (bucket.timestamps.length === 0) rateBuckets.delete(key);
  }
}, 300_000).unref();

function rateLimit(windowMs: number, maxRequests: number): express.RequestHandler {
  return (req, res, next) => {
    const ip = req.ip ?? req.socket.remoteAddress ?? 'unknown';
    const key = `${req.route?.path ?? req.path}:${ip}`;
    const now = Date.now();
    const bucket = rateBuckets.get(key) ?? { timestamps: [] };

    bucket.timestamps = bucket.timestamps.filter((t) => t > now - windowMs);
    if (bucket.timestamps.length >= maxRequests) {
      res.set('Retry-After', String(Math.ceil(windowMs / 1000)));
      return res.status(429).json({ error: 'Too many requests, please try again later' });
    }

    bucket.timestamps.push(now);
    rateBuckets.set(key, bucket);
    return next();
  };
}

// 5 proposals per minute per IP.
const proposalLimiter = rateLimit(60_000, 5);
// 30 signature submissions per minute per IP.
const callbackLimiter = rateLimit(60_000, 30);
// 10 document-hash requests per minute per IP.
const docHashLimiter = rateLimit(60_000, 10);

// ---------------------------------------------------------------------------
// API key authentication middleware for proposal creation.
// When ORGANIZER_API_KEY is set, the caller must provide a valid
// "Authorization: Bearer <key>" header. When unset, proposal creation is
// allowed without authentication (convenient for local development).
// ---------------------------------------------------------------------------
function authRequired(req: express.Request, res: express.Response, next: express.NextFunction): void {
  // When no API key is configured, allow unauthenticated access (development mode).
  if (organizerApiKey === '') {
    next();
    return;
  }

  const authHeader = req.headers.authorization ?? '';
  const match = /^Bearer\s+(.+)$/i.exec(authHeader);
  const token = match?.[1] ?? '';

  if (token.length === 0) {
    res.status(401).json({ error: 'Missing or invalid API key' });
    return;
  }

  // Use timing-safe comparison to prevent timing attacks.
  const expected = Buffer.from(organizerApiKey, 'utf8');
  const received = Buffer.from(token, 'utf8');

  if (expected.length !== received.length || !timingSafeEqual(expected, received)) {
    res.status(401).json({ error: 'Missing or invalid API key' });
    return;
  }

  next();
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true });
});

app.get('/api/downloads', (_req, res) => {
  const download = `${releaseBaseURL.replace(/\/$/, '')}/download`;
  res.json({
    releasesPage: releaseBaseURL,
    binaries: [
      {
        id: 'windows-amd64',
        os: 'Windows',
        arch: 'x64',
        filename: 'vocsign-windows-amd64.exe',
        url: `${download}/vocsign-windows-amd64.exe`
      },
      {
        id: 'macos-amd64',
        os: 'macOS',
        arch: 'Intel',
        filename: 'vocsign-darwin-amd64',
        url: `${download}/vocsign-darwin-amd64`
      },
      {
        id: 'macos-arm64',
        os: 'macOS',
        arch: 'Apple Silicon',
        filename: 'vocsign-darwin-arm64',
        url: `${download}/vocsign-darwin-arm64`
      },
      {
        id: 'linux-amd64',
        os: 'Linux',
        arch: 'x64',
        filename: 'vocsign-linux-amd64',
        url: `${download}/vocsign-linux-amd64`
      }
    ]
  });
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

// ---------------------------------------------------------------------------
// Compute SHA-256 of a remote document (the full text PDF).
// The frontend cannot fetch arbitrary URLs due to CORS, so we proxy it here.
// ---------------------------------------------------------------------------
const MAX_DOC_BYTES = 50 * 1024 * 1024; // 50 MB

app.post('/api/hash-document', docHashLimiter, async (req, res) => {
  const { url } = req.body ?? {};
  if (typeof url !== 'string' || url.trim() === '') {
    return res.status(400).json({ error: 'Missing "url" field' });
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return res.status(400).json({ error: 'Invalid URL' });
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return res.status(400).json({ error: 'URL must use http or https' });
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);

    const upstream = await fetch(url, {
      signal: controller.signal,
      headers: { 'Accept': '*/*' },
      redirect: 'follow'
    });
    clearTimeout(timeout);

    if (!upstream.ok) {
      return res.status(502).json({ error: `Document fetch failed: HTTP ${upstream.status}` });
    }

    const contentLength = Number(upstream.headers.get('content-length') ?? 0);
    if (contentLength > MAX_DOC_BYTES) {
      return res.status(413).json({ error: `Document too large (${contentLength} bytes, max ${MAX_DOC_BYTES})` });
    }

    const chunks: Buffer[] = [];
    let totalBytes = 0;
    for await (const chunk of upstream.body as AsyncIterable<Uint8Array>) {
      totalBytes += chunk.length;
      if (totalBytes > MAX_DOC_BYTES) {
        return res.status(413).json({ error: `Document too large (max ${MAX_DOC_BYTES} bytes)` });
      }
      chunks.push(Buffer.from(chunk));
    }

    const body = Buffer.concat(chunks);
    const hash = createHash('sha256').update(body).digest('base64');
    return res.json({ sha256: hash });
  } catch (err) {
    if (err instanceof Error && err.name === 'AbortError') {
      return res.status(504).json({ error: 'Document fetch timed out' });
    }
    return res.status(502).json({ error: 'Could not fetch document' });
  }
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

app.post('/api/proposals', proposalLimiter, async (req, res) => {
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
        sha256: proposal.fullTextSHA256
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

app.post('/api/callback/:requestId', callbackLimiter, async (req, res) => {
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

  // Validate signedAt timestamp against server clock.
  const signedAtDate = new Date(signResponse.signedAt);
  const now = Date.now();
  const fiveMinutesMs = 5 * 60 * 1000;
  const twentyFourHoursMs = 24 * 60 * 60 * 1000;
  if (
    Number.isNaN(signedAtDate.getTime()) ||
    signedAtDate.getTime() > now + fiveMinutesMs ||
    signedAtDate.getTime() < now - twentyFourHoursMs
  ) {
    return res.status(400).json({ error: 'signedAt timestamp is outside acceptable range' });
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

  // Verify the CAdES detached signature is valid and matches the content.
  try {
    await verifyCadesDetached(
      signResponse.signatureDerBase64,
      signResponse.signerXmlBase64,
      signResponse.signerCertPem,
      signResponse.chainPem ?? [],
      signResponse.signedAt
    );
  } catch (err) {
    console.error('Signature verification failed:', err);
    return res.status(400).json({
      error: 'Signature verification failed'
    });
  }

  // Cross-check: the identity in the XML must match the certificate subject.
  try {
    const certIdentity = extractCertIdentity(signResponse.signerCertPem);
    if (certIdentity.signerId !== signer.signerId) {
      return res.status(400).json({ error: 'signer identity in XML does not match certificate subject' });
    }
  } catch (err) {
    console.error('Failed to extract identity from certificate:', err);
    return res.status(400).json({
      error: 'Failed to extract identity from certificate'
    });
  }

  // Friendly early check: an ID can sign only once per proposal.
  const alreadySigned = await SignatureModel.exists({ requestId, signerId: signer.signerId });
  if (alreadySigned) {
    return res.status(409).json({ error: 'This ID has already signed this proposal' });
  }

  const session = await mongoose.startSession();
  try {
    await session.withTransaction(async () => {
      await SignatureModel.create(
        [
          {
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
            timestampTokenBase64: signResponse.timestampTokenBase64 ?? '',
            client: {
              app: signResponse.client?.app ?? '',
              version: signResponse.client?.version ?? '',
              os: signResponse.client?.os ?? ''
            }
          }
        ],
        { session }
      );
      await ProposalModel.updateOne({ requestId }, { $inc: { signaturesCount: 1 } }, { session });
    });
  } catch (err) {
    if (isDuplicateKeyError(err)) {
      return res.status(409).json({ error: 'This ID has already signed this proposal' });
    }
    console.error(err);
    return res.status(500).json({ error: 'Could not store signature' });
  } finally {
    await session.endSession();
  }

  return res.status(201).json({
    status: 'accepted',
    requestId,
    signaturesCount: proposal.signaturesCount + 1
  });
});

// ---------------------------------------------------------------------------
// GDPR right-to-erasure: delete all signatures for a given signer ID.
// Requires API key authentication.
// ---------------------------------------------------------------------------
app.delete('/api/signatures/:signerId', authRequired, async (req, res) => {
  const signerId = String(req.params.signerId ?? '').trim();
  if (signerId.length === 0) {
    return res.status(400).json({ error: 'signerId is required' });
  }

  const result = await SignatureModel.deleteMany({ signerId: signerId.toUpperCase() });
  if (result.deletedCount === 0) {
    return res.status(404).json({ error: 'No signatures found for this signer ID' });
  }

  // Recalculate signature counts for affected proposals.
  const proposals = await SignatureModel.aggregate([
    { $group: { _id: '$requestId', count: { $sum: 1 } } }
  ]);
  const countMap = new Map(proposals.map((p) => [p._id as string, p.count as number]));
  const allProposals = await ProposalModel.find({});
  for (const proposal of allProposals) {
    const newCount = countMap.get(proposal.requestId) ?? 0;
    if (proposal.signaturesCount !== newCount) {
      await ProposalModel.updateOne({ requestId: proposal.requestId }, { signaturesCount: newCount });
    }
  }

  return res.json({
    deleted: result.deletedCount,
    signerId: signerId.toUpperCase(),
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
  try {
    const redacted = new URL(mongoUri);
    if (redacted.password) redacted.password = '***';
    console.log(`Connected to MongoDB at ${redacted.href}`);
  } catch {
    console.log('Connected to MongoDB');
  }
  if (organizerApiKey === '') {
    console.warn('WARNING: ORGANIZER_API_KEY is not set — proposal creation endpoint is unauthenticated');
  }
  if (process.env.ALLOW_TEST_CERTS === 'true') {
    console.warn('WARNING: ALLOW_TEST_CERTS is enabled — certificate chain and revocation checks are DISABLED');
  }
  app.listen(port, () => {
    console.log(`Vocsign portal listening on http://0.0.0.0:${port}`);
  });
}

bootstrap().catch((err) => {
  console.error('Fatal startup error', err);
  process.exit(1);
});
