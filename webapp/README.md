# Vocsign portal webapp

Production-oriented collector portal for creating signature proposals and tracking signatures.

## Stack

- Frontend: Vite + React + TypeScript
- Backend: Node.js + Express + TypeScript
- Database: MongoDB
- Containerization: Docker + docker-compose

## Features

- Public proposal creation with organizer-focused fields (technical manifest fields are backend-generated).
- Proposal dashboard with sorting by recent or signature count.
- Proposal page with signing URL, progress bar, and signature count.
- Embedded participation guide with Vocsign binary download link.
- Callback endpoint to store signatures and signer accountability metadata.
- Per-proposal signer uniqueness by ID (one ID can sign only once).
- Signer identity details are stored privately and not exposed in public endpoints.

## Run with Docker

```bash
cd webapp
docker compose up --build
```

Portal will be available at `http://localhost:8080`.

## Local development

```bash
cd webapp
npm install
npm run dev
```

- API: `http://localhost:8080`
- Web (Vite dev): `http://localhost:5173`

## Environment

Use `.env.example` as reference:

- `PORT`
- `MONGODB_URI`
- `PORTAL_DOMAIN_URL` (for generated signing and callback links, e.g. `https://proposals.net`)
- `ORGANIZER_KID`
- `ORGANIZER_JWKS_URL`
- `ORGANIZER_PRIVATE_KEY_HEX` (32-byte private scalar, 64 hex chars)
- `POLICY_OID`
- `POLICY_URI`
- `DEFAULT_PROPOSAL_VALIDITY_DAYS`

## Generate organizer private key (hex)

Generate a random 32-byte hex private key:

```bash
openssl rand -hex 32
```

Use it in `.env`:

```bash
ORGANIZER_PRIVATE_KEY_HEX=0123abcd...64hexchars
```

Notes:

- Keep this key secret; it is used to sign proposal manifests.
- Only EC P-256 keys are supported in this dev setup.
- `ORGANIZER_PRIVATE_KEY_HEX` must be exactly 64 hexadecimal characters.
- `ORGANIZER_PRIVATE_KEY_HEX` is required; backend startup fails if it is missing.
