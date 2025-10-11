import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'

const base =
  import.meta.env.VITE_API_BASE ||
  import.meta.env.VITE_API_BASE_URL ||
  ''

function loadSession() {
  try { return JSON.parse(localStorage.getItem('auth') || 'null') } catch { return null }
}

export default function WhoAmI() {
  const nav = useNavigate()
  const [me, setMe] = useState(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    const s = loadSession()
    if (!s?.token) { nav('/', { replace: true }); return }
    fetch(base + '/whoami', {
      headers: { Authorization: `Bearer ${s.token}` }
    })
      .then(r => r.ok ? r.json() : r.text().then(t => Promise.reject(t || r.status)))
      .then(setMe)
      .catch(e => setErr(String(e)))
  }, [nav])

  const logout = () => {
    localStorage.removeItem('auth')
    nav('/', { replace: true })
  }

  return (
    <div style={{ maxWidth: 720, margin: '40px auto', background: 'white', borderRadius: 12, padding: 24 }}>
      <h3>WhoAmI</h3>
      {err && <pre style={{ color: 'crimson' }}>{err}</pre>}
      {me ? <pre>{JSON.stringify(me, null, 2)}</pre> : <div>Loading…</div>}
      <button onClick={logout} style={{ marginTop: 16 }}>Logout</button>
    </div>
  )
}
