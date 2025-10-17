import { NavLink, Navigate, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useEffect } from 'react'
import { clearSession, getSession } from '../lib/session'
import { logInfo } from '../lib/logger.js'

const links = [
  { to: '/app', label: 'Overview', end: true },
  { to: '/app/secrets', label: 'Manage secrets' },
  { to: '/app/configs', label: 'Manage configs' },
  { to: '/app/users', label: 'Manage users' },
  { to: '/app/audit', label: 'Audit log' }
]

export default function AppLayout() {
  const session = getSession()
  const location = useLocation()
  const navigate = useNavigate()

  if (!session?.token) {
    return <Navigate to="/" replace state={{ from: location }} />
  }

  const { user } = session
  const displayName =
    user?.username ||
    user?.subject ||
    user?.name ||
    user?.email ||
    user?.id ||
    'Operator'

  useEffect(() => {
    logInfo('nav.location', { path: location.pathname })
  }, [location.pathname])

  const logout = () => {
    clearSession()
    navigate('/', { replace: true })
    logInfo('auth.logout', { path: location.pathname })
    setTimeout(() => {
      if (!window.location.hash.startsWith('#/')) {
        window.location.hash = '#/'
      }
    }, 0)
  }

  return (
    <div className="app-shell">
      <aside className="app-sidebar">
        <div className="app-brand">
          ConSecMaster
          <span className="app-brand-tagline">Secrets &amp; Config Manager</span>
        </div>
        <nav className="app-nav">
          {links.map(({ to, label, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) => isActive ? 'app-nav-link active' : 'app-nav-link'}
            >
              {label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <div className="app-main">
        <header className="app-header">
          <div>
            <div className="app-hello">Hello, {displayName}</div>
            {user?.roles && user.roles.length > 0 && (
              <div className="app-role">Roles: {user.roles.join(', ')}</div>
            )}
          </div>
          <button type="button" className="app-logout" onClick={logout}>Logout</button>
        </header>
        <main className="app-content">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
