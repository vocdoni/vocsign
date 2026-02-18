import type { CreateProposalInput, DownloadsResponse, ProposalDetails, ProposalListItem } from './types';

async function handleJSON<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error ?? 'Request failed');
  }
  return response.json() as Promise<T>;
}

export async function listProposals(sort: 'recent' | 'signatures'): Promise<ProposalListItem[]> {
  const res = await fetch(`/api/proposals?sort=${sort}`);
  return handleJSON<ProposalListItem[]>(res);
}

export async function createProposal(payload: CreateProposalInput): Promise<{
  requestId: string;
  signingURL: string;
  targetSignatures: number;
  signaturesCount: number;
}> {
  const res = await fetch('/api/proposals', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  return handleJSON(res);
}

export async function getProposal(requestId: string): Promise<ProposalDetails> {
  const res = await fetch(`/api/proposals/${encodeURIComponent(requestId)}`);
  return handleJSON<ProposalDetails>(res);
}

export async function getDownloads(): Promise<DownloadsResponse> {
  const res = await fetch('/api/downloads');
  return handleJSON<DownloadsResponse>(res);
}
