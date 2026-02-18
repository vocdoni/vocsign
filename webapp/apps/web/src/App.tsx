import { Navigate, Route, Routes } from 'react-router-dom';

import { Header } from './components/Header';
import { CreateProposalPage } from './pages/CreateProposalPage';
import { DashboardPage } from './pages/DashboardPage';
import { HowToSignPage } from './pages/HowToSignPage';
import { ProposalPage } from './pages/ProposalPage';

export function App(): JSX.Element {
  return (
    <div className="app-shell">
      <Header />
      <main>
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/proposals/new" element={<CreateProposalPage />} />
          <Route path="/proposals/:requestId" element={<ProposalPage />} />
          <Route path="/how-to-sign" element={<HowToSignPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}
