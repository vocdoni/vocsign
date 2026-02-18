import { Link, NavLink } from 'react-router-dom';

export function Header(): JSX.Element {
  return (
    <header className="site-header">
      <div className="container header-inner">
        <Link to="/" className="brand">
          <img src="/vocdoni-logo.png" alt="Vocdoni" className="brand-logo" />
        </Link>
        <nav className="main-nav">
          <NavLink to="/" end>
            Dashboard
          </NavLink>
          <NavLink to="/proposals/new">Create proposal</NavLink>
          <NavLink to="/how-to-sign">How to sign</NavLink>
        </nav>
      </div>
    </header>
  );
}
