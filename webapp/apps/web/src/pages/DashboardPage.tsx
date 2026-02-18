import { useEffect, useState } from 'react';
import { ArrowRight, PlusCircle } from 'lucide-react';
import { Link } from 'react-router-dom';

import { listProposals } from '../api';
import { ProgressBar } from '../components/ProgressBar';
import type { ProposalListItem } from '../types';

export function DashboardPage(): JSX.Element {
  const [sort, setSort] = useState<'recent' | 'signatures'>('recent');
  const [proposals, setProposals] = useState<ProposalListItem[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    setError('');
    listProposals(sort)
      .then((items) => setProposals(items))
      .catch((err: unknown) => setError(err instanceof Error ? err.message : 'Could not load proposals'))
      .finally(() => setLoading(false));
  }, [sort]);

  return (
    <section className="container stack-lg">
      <div className="hero">
        <div>
          <p className="eyebrow">Vocsign Portal</p>
          <h2>Sign legally binding legislative proposals</h2>
          <p>
            Signatures follow legal standards and requirements using only official issued certificates. Create proposals,
            share signing links, and track progress in real time.
          </p>
        </div>
        <img src="/hero-illustration.svg" alt="Digital signing" />
      </div>

      <div className="toolbar">
        <div className="sort-control">
          <label htmlFor="sort">Sort by</label>
          <select id="sort" value={sort} onChange={(e) => setSort(e.target.value as 'recent' | 'signatures')}>
            <option value="recent">Most recent</option>
            <option value="signatures">Most signatures</option>
          </select>
        </div>
        <Link to="/proposals/new" className="btn btn-primary">
          <PlusCircle size={16} /> Create a new proposal
        </Link>
      </div>

      {loading ? <p>Loading proposals...</p> : null}
      {error ? <p className="error-box">{error}</p> : null}

      <div className="proposal-grid">
        {proposals.map((item) => (
          <article key={item.requestId} className="proposal-card">
            <p className="meta">{new Date(item.createdAt).toLocaleDateString()}</p>
            <h3>{item.title}</h3>
            <p className="promoter">{item.promoter}</p>
            <p>{item.summary}</p>
            <ProgressBar current={item.signaturesCount} target={item.targetSignatures} />
            <div className="card-actions">
              <Link to={`/proposals/${encodeURIComponent(item.requestId)}`} className="btn btn-ghost">
                Open proposal <ArrowRight size={16} />
              </Link>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}
