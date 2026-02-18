import { useEffect, useState } from 'react';
import { CheckCircle2, Download, ExternalLink, FileCheck2, Link2, ShieldCheck } from 'lucide-react';

import { getDownloads } from '../api';
import type { DownloadsResponse } from '../types';

interface SignerGuideProps {
  signingURL?: string;
}

export function SignerGuide({ signingURL }: SignerGuideProps): JSX.Element {
  const [downloads, setDownloads] = useState<DownloadsResponse | null>(null);
  const [downloadsError, setDownloadsError] = useState('');

  useEffect(() => {
    getDownloads()
      .then(setDownloads)
      .catch((err: unknown) => setDownloadsError(err instanceof Error ? err.message : 'Could not load download links'));
  }, []);

  return (
    <section className="guide-card">
      <h3>How to participate as a signer</h3>
      <p>Use Vocsign desktop app to read the proposal request, review legal text, and submit your qualified signature.</p>
      <ol className="steps">
        <li>
          <Download size={16} />
          <span>
            Download Vocsign from the{' '}
            <a href={downloads?.releasesPage ?? 'https://github.com/vocdoni/vocsign/releases/latest'} target="_blank" rel="noreferrer">
              latest release page <ExternalLink size={14} />
            </a>
            .
          </span>
        </li>
        <li>
          <ShieldCheck size={16} />
          <span>Open Vocsign and import your valid certificate if needed.</span>
        </li>
        <li>
          <Link2 size={16} />
          <span>Use the proposal signing URL shown below.</span>
        </li>
        <li>
          <FileCheck2 size={16} />
          <span>Review proposal title, summary and legal statement before signing.</span>
        </li>
        <li>
          <CheckCircle2 size={16} />
          <span>Confirm signature. Your signature count appears on this page immediately.</span>
        </li>
      </ol>
      <div className="download-grid">
        {(downloads?.binaries ?? []).map((binary) => (
          <a key={binary.id} className="btn btn-secondary" href={binary.url} target="_blank" rel="noreferrer">
            <Download size={15} />
            {binary.os} ({binary.arch})
          </a>
        ))}
      </div>
      {downloadsError ? <p className="error-box">{downloadsError}</p> : null}
      {signingURL ? (
        <div className="sign-url-box">
          <p>Signing URL</p>
          <code>{signingURL}</code>
        </div>
      ) : null}
    </section>
  );
}
