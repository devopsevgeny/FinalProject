import { useState } from 'react'
import { api } from '../api.js'

export default function ConfigPage() {
  const [path, setPath] = useState('app/feature-flags')
  const [json, setJson] = useState('{"beta_ui": true, "limit": 50}')
  const [out, setOut] = useState(null)
  const [err, setErr] = useState(null)

  const write = async () => {
    setErr(null)
    try { const body = { value: JSON.parse(json) }; const { data } = await api.post(`/config/${encodeURIComponent(path)}`, body); setOut(data) }
    catch(e){ setErr(e?.response?.data?.detail || 'Write failed') }
  }
  const read = async () => {
    setErr(null)
    try { const { data } = await api.get(`/config/${encodeURIComponent(path)}`); setOut(data); setJson(JSON.stringify(data.value ?? {}, null, 2)) }
    catch(e){ setErr(e?.response?.data?.detail || 'Read failed') }
  }

  return (
    <div className="d-grid gap-3" style={{maxWidth:880}}>
      <h3>Config</h3>
      <input value={path} onChange={e=>setPath(e.target.value)} placeholder="path (e.g. app/feature-flags)" />
      <div className="d-flex gap-3">
        <button onClick={write}>Create/Update (POST)</button>
        <button onClick={read}>Read current</button>
      </div>
      <textarea rows={10} value={json} onChange={e=>setJson(e.target.value)} />
      {err && <div className="text-danger">{err}</div>}
      {out && <pre>{JSON.stringify(out,null,2)}</pre>}
    </div>
  )
}
