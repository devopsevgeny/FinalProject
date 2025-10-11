import { useState } from 'react'
import { api } from '../api.js'

export default function Secret() {
  const [path, setPath] = useState('service/api')
  const [username, setU] = useState('alice')
  const [password, setP] = useState('s3cr3t')
  const [version, setV] = useState('')
  const [out, setOut] = useState(null)
  const [err, setErr] = useState(null)

  const readCurrent = async () => { setErr(null); try{ const {data}=await api.get(`/secret/${encodeURIComponent(path)}`); setOut(data) }catch(e){ setErr(e?.response?.data?.detail||'Read failed') } }
  const readVersion = async () => { if(version==='')return; setErr(null); try{ const {data}=await api.get(`/secret/${encodeURIComponent(path)}?version=${version}`); setOut(data) }catch(e){ setErr(e?.response?.data?.detail||'Read vN failed') } }
  const write = async () => { setErr(null); try{ const {data}=await api.post(`/secret/${encodeURIComponent(path)}`, { value: { username, password } }); setOut(data) }catch(e){ setErr(e?.response?.data?.detail||'Write failed') } }

  return (
    <div className="d-grid gap-3" style={{maxWidth:720}}>
      <h3>Secret</h3>
      <input value={path} onChange={e=>setPath(e.target.value)} placeholder="path (e.g. service/api)" />
      <div className="d-flex gap-3">
        <input value={username} onChange={e=>setU(e.target.value)} placeholder="username" />
        <input value={password} onChange={e=>setP(e.target.value)} placeholder="password" />
      </div>
      <div className="d-flex gap-3">
        <button onClick={write}>Create/Rotate (POST)</button>
        <button onClick={readCurrent}>Read current</button>
        <input style={{width:120}} value={version} onChange={e=>setV(e.target.value)} placeholder="version (e.g. 1)" />
        <button onClick={readVersion} disabled={version===''}>Read vN</button>
      </div>
      {err && <div className="text-danger">{err}</div>}
      {out && <pre>{JSON.stringify(out,null,2)}</pre>}
    </div>
  )
}
