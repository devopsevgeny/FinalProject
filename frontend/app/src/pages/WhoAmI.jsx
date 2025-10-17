import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getSession, clearSession } from '../lib/session'
import { logInfo, logError } from '../lib/logger.js'

const base =
  import.meta.env.VITE_API_BASE ||
  import.meta.env.VITE_API_BASE_URL ||
  ''

export default function WhoAmI() {
  const nav = useNavigate()
  const [me, setMe] = useState(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    const s = getSession()
    if (!s?.token) {
      logInfo('auth.session.missing', 'Redirecting to login from /whoami')
      nav('/', { replace: true })
      return
    }
    logInfo('whoami.fetch.request')
    fetch(base + '/whoami', {
      headers: { Authorization: `Bearer ${s.token}` }
    })
      .then(r => r.ok ? r.json() : r.text().then(t => Promise.reject(t || r.status)))
      .then(data => {
        logInfo('whoami.fetch.success')
        setMe(data)
      })
      .catch(e => {
        logError('whoami.fetch.error', { message: String(e) })
        setErr(String(e))
      })
  }, [nav])

  const logout = () => {
    clearSession()
    nav('/', { replace: true })
  }

  return (
    <div className="d-grid gap-3" style={{ maxWidth: 720 }}>
      <h3 style={{ marginTop: 0 }}>Token details</h3>
      <p style={{ marginBottom: 0 }}>Raw payload returned by <code>/whoami</code>.</p>
      {err && <pre style={{ color: 'crimson' }}>{err}</pre>}
      {me ? <pre>{JSON.stringify(me, null, 2)}</pre> : <div>Loading…</div>}
      <div>
        <button onClick={logout} style={{ marginTop: 8 }}>Logout</button>
      </div>
    </div>
  )
}
