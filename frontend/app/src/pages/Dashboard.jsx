import { Link } from 'react-router-dom'
import { getSession } from '../lib/session'

const cards = [
  {
    title: 'Manage secrets',
    description: 'Rotate service credentials, inspect previous versions, and verify stored values.',
    to: '/app/secrets'
  },
  {
    title: 'Manage configs',
    description: 'View and update configuration documents with full version history.',
    to: '/app/configs'
  },
  {
    title: 'Manage users',
    description: 'Plan user lifecycle policies while the backend API is being built.',
    to: '/app/users'
  },
  {
    title: 'Audit log',
    description: 'Review the audit trail recorded by backend services.',
    to: '/app/audit'
  },
  {
    title: 'Token details',
    description: 'Inspect the raw identity payload issued for this session.',
    to: '/app/whoami'
  }
]

export default function Dashboard() {
  const session = getSession()
  const user = session?.user || {}

  return (
    <div className="dashboard">
      <h2 style={{ marginTop: 0 }}>Control center</h2>
      <p style={{ marginBottom: 24, color: '#475569' }}>
        You are authenticated as <strong>{user.username || user.email || user.id || 'unknown user'}</strong>.
        Use the tiles below to jump into each area of the configuration manager.
      </p>
      <div className="app-card-grid">
        {cards.map(card => (
          <div key={card.to} className="app-card">
            <h4>{card.title}</h4>
            <p>{card.description}</p>
            <Link to={card.to}>Open</Link>
          </div>
        ))}
      </div>
    </div>
  )
}
