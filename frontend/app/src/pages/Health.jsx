import { useEffect, useState } from 'react'
import { api } from '../api.js'

export default function Health() {
  const [data, setData] = useState(null)
  const [err, setErr] = useState(null)
  useEffect(()=>{ api.get('/health').then(r=>setData(r.data)).catch(setErr) },[])
  return <div><h3>Health</h3>{err ? <div className="text-danger">Error</div> : data ? <pre>{JSON.stringify(data,null,2)}</pre> : 'Loading…'}</div>
}
