import { useEffect, useMemo, useState } from 'react';
import { BookOpen, Check, Copy, Users } from 'lucide-react';
import { useParams } from 'react-router-dom';

import { getProposal } from '../api';
import { ProgressBar } from '../components/ProgressBar';
import { SignerGuide } from '../components/SignerGuide';
import type { ProposalDetails } from '../types';

export function ProposalPage(): JSX.Element {
  const { requestId = '' } = useParams();
  const [proposal, setProposal] = useState<ProposalDetails | null>(null);
  const [error, setError] = useState('');
  const [showGuide, setShowGuide] = useState(false);
  const [copyState, setCopyState] = useState<'idle' | 'success' | 'error'>('idle');

  useEffect(() => {
    setError('');
    getProposal(requestId)
      .then(setProposal)
      .catch((err: unknown) => setError(err instanceof Error ? err.message : 'Could not load proposal'));
  }, [requestId]);

  const progressTitle = useMemo(() => {
    if (!proposal) {
      return '';
    }
    return proposal.reachedTarget ? 'Target achieved' : 'Collecting signatures';
  }, [proposal]);

  async function copySigningURL(): Promise<void> {
    if (!proposal) {
      return;
    }
    try {
      await navigator.clipboard.writeText(proposal.signingURL);
      setCopyState('success');
    } catch {
      setCopyState('error');
    }
    window.setTimeout(() => setCopyState('idle'), 1600);
  }

  if (error) {
    return (
      <section className="container">
        <p className="error-box">{error}</p>
      </section>
    );
  }

  if (!proposal) {
    return (
      <section className="container">
        <p>Loading proposal...</p>
      </section>
    );
  }

  return (
    <section className="container stack-lg">
      <article className="proposal-detail">
        <p className="eyebrow">Proposal {proposal.requestId}</p>
        <h2>{proposal.manifest.proposal.title}</h2>
        <p className="promoter">Promoter: {proposal.manifest.proposal.promoter}</p>
        <p>{proposal.manifest.proposal.summary}</p>

        <div className="stats-row">
          <div className="stat-card">
            <Users size={18} />
            <div>
              <p>Signatures</p>
              <strong>{proposal.signaturesCount}</strong>
            </div>
          </div>
          <div className="stat-card">
            <BookOpen size={18} />
            <div>
              <p>Status</p>
              <strong>{progressTitle}</strong>
            </div>
          </div>
        </div>

        <ProgressBar current={proposal.signaturesCount} target={proposal.targetSignatures} />

        <div className="sign-url-box">
          <p>Signing URL</p>
          <code>{proposal.signingURL}</code>
          <button
            className={`btn btn-secondary ${copyState === 'success' ? 'btn-success' : ''} ${
              copyState === 'error' ? 'btn-error' : ''
            }`}
            onClick={copySigningURL}
          >
            {copyState === 'success' ? <Check size={16} /> : <Copy size={16} />}
            {copyState === 'success' ? 'Copied' : copyState === 'error' ? 'Copy failed' : 'Copy URL'}
          </button>
        </div>

        <div className="card-actions">
          <button className="btn btn-primary" onClick={() => setShowGuide((prev) => !prev)}>
            {showGuide ? 'Hide participation guide' : 'Participate'}
          </button>
          <a className="btn btn-ghost" href={proposal.manifest.proposal.fullText.url} target="_blank" rel="noreferrer">
            Open full text
          </a>
        </div>
      </article>

      {showGuide ? <SignerGuide signingURL={proposal.signingURL} /> : null}
    </section>
  );
}
