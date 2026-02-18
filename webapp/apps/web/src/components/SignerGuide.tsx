import { CheckCircle2, Download, ExternalLink, FileCheck2, Link2, ShieldCheck } from 'lucide-react';

interface SignerGuideProps {
  signingURL?: string;
}

export function SignerGuide({ signingURL }: SignerGuideProps): JSX.Element {
  return (
    <section className="guide-card">
      <h3>How to participate as a signer</h3>
      <p>Use Vocsign desktop app to read the proposal request, review legal text, and submit your qualified signature.</p>
      <ol className="steps">
        <li>
          <Download size={16} />
          <span>
            Download Vocsign binaries from{' '}
            <a href="https://github.com/vocdoni/vocsign/tree/main/build" target="_blank" rel="noreferrer">
              GitHub build artifacts <ExternalLink size={14} />
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
      {signingURL ? (
        <div className="sign-url-box">
          <p>Signing URL</p>
          <code>{signingURL}</code>
        </div>
      ) : null}
    </section>
  );
}
