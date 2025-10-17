import { useState, useEffect, useCallback } from 'react'
import { api } from '../api.js'
import { logInfo, logError } from '../lib/logger.js'

const MASK = '**********'

function entriesFromValue(value) {
  if (!value || typeof value !== 'object') return []
  return Object.entries(value).map(([key, val]) => ({
    key,
    value: String(val ?? ''),
    masked: true
  }))
}

function buildPayload(rows) {
  return rows.reduce((acc, row) => {
    const key = row.key.trim()
    if (!key) return acc
    acc[key] = row.value
    return acc
  }, {})
}

export default function SecretManager() {
  const [appId, setAppId] = useState('default')
  const [appName, setAppName] = useState('')
  const [path, setPath] = useState('')
  const [rows, setRows] = useState([
    { key: 'username', value: '', masked: true },
    { key: 'password', value: '', masked: true }
  ])
  const [version, setVersion] = useState('')

  const [items, setItems] = useState([])
  const [listLoading, setListLoading] = useState(false)
  const [listErr, setListErr] = useState(null)

  const [err, setErr] = useState(null)
  const [out, setOut] = useState(null)
  const [showPreview, setShowPreview] = useState(false)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [saving, setSaving] = useState(false)

  const loadSecrets = useCallback(async () => {
    const trimmedAppId = (appId || '').trim()
    if (!trimmedAppId) {
      setItems([])
      setListErr('Provide an App ID to load secrets.')
      return
    }
    setListLoading(true)
    setListErr(null)
    logInfo('secret.list.request', { appId: trimmedAppId })
    try {
      const { data } = await api.get(`/secret/?appId=${encodeURIComponent(trimmedAppId)}`)
      const normalized = Array.isArray(data)
        ? data.map(item => ({
            ...item,
            app_id: item.app_id || trimmedAppId,
            app_name: item.app_name || item.appId || ''
          }))
        : []
      setItems(normalized)
      logInfo('secret.list.success', { appId: trimmedAppId, count: normalized.length })
    } catch (e) {
      const message = e?.response?.data?.detail || 'Failed to load secrets'
      setListErr(message)
      logError('secret.list.error', { appId: trimmedAppId, message })
    } finally {
      setListLoading(false)
    }
  }, [appId])

  useEffect(() => {
    loadSecrets()
  }, [loadSecrets])

  const handleRowChange = (index, field, value) => {
    setRows(prev => prev.map((row, i) => (i === index ? { ...row, [field]: value } : row)))
  }

  const toggleMask = (index) => {
    setRows(prev => prev.map((row, i) => (i === index ? { ...row, masked: !row.masked } : row)))
  }

  const addRow = () => {
    setRows(prev => [...prev, { key: '', value: '', masked: true }])
  }

  const removeRow = (index) => {
    setRows(prev => prev.filter((_, i) => i !== index))
  }

  const fetchSecret = useCallback(async ({ targetPath, targetVersion = null }) => {
    const trimmedPath = (targetPath || '').trim()
    if (!trimmedPath) {
      setErr('Provide a secret path first.')
      return
    }
    const trimmedAppId = (appId || '').trim() || 'default'
    setErr(null)
    setPreviewLoading(true)
    setShowPreview(false)
    const logPayload = { appId: trimmedAppId, path: trimmedPath, version: targetVersion ?? 'current' }
    logInfo('secret.read.request', logPayload)
    try {
      const base = `/secret/${encodeURIComponent(trimmedPath)}`
      const params = new URLSearchParams({ appId: trimmedAppId })
      if (targetVersion) params.set('version', targetVersion)
      const url = `${base}?${params.toString()}`
      const { data } = await api.get(url)
      logInfo('secret.read.success', logPayload)
      setOut(data)
      if (data.app_id) setAppId(data.app_id)
      if (data.app_name) setAppName(data.app_name)
    } catch (e) {
      const message = e?.response?.data?.detail || 'Read failed'
      logError('secret.read.error', { ...logPayload, message })
      setErr(message)
    } finally {
      setPreviewLoading(false)
    }
  }, [appId])

  const writeSecret = async () => {
    const trimmedPath = path.trim()
    if (!trimmedPath) {
      setErr('Provide a secret path.')
      return
    }
    const payload = buildPayload(rows)
    if (Object.keys(payload).length === 0) {
      setErr('Add at least one key/value pair.')
      return
    }

    const trimmedAppId = (appId || '').trim()
    if (!trimmedAppId) {
      setErr('Provide an App ID.')
      return
    }

    setErr(null)
    setSaving(true)
    logInfo('secret.write.request', { appId: trimmedAppId, path: trimmedPath, keys: Object.keys(payload) })
    try {
      const body = {
        app_id: trimmedAppId,
        app_name: appName?.trim() || undefined,
        value: payload
      }
      const { data } = await api.post(`/secret/${encodeURIComponent(trimmedPath)}`, body)
      logInfo('secret.write.success', { appId: trimmedAppId, path: trimmedPath, version: data?.version })
      setOut(data)
      if (data.app_id) setAppId(data.app_id)
      if (data.app_name) setAppName(data.app_name)
      setShowPreview(false)
      loadSecrets()
    } catch (e) {
      const message = e?.response?.data?.detail || 'Write failed'
      logError('secret.write.error', { appId: trimmedAppId, path: trimmedPath, message })
      setErr(message)
    } finally {
      setSaving(false)
    }
  }

  const handleSelectSecret = async (item) => {
    setPath(item.path)
    setVersion('')
    if (item.app_id) setAppId(item.app_id)
    if (item.app_name) setAppName(item.app_name)
    await fetchSecret({ targetPath: item.path })
  }

  const loadIntoEditor = () => {
    if (!out?.value) return
    const nextRows = entriesFromValue(out.value)
    setRows(nextRows.length ? nextRows : [{ key: '', value: '', masked: true }])
    setShowPreview(true)
    if (out.app_id) setAppId(out.app_id)
    if (out.app_name) setAppName(out.app_name)
    if (out.path) setPath(out.path)
  }

  return (
    <div className="secret-layout">
      <aside className="secret-sidebar">
        <div className="secret-sidebar-header">
          <h4>Secrets</h4>
          <button type="button" onClick={loadSecrets} disabled={listLoading}>
            {listLoading ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
        {listErr && <div className="text-danger">{listErr}</div>}
        {!listErr && items.length === 0 && !listLoading && (
          <div className="secret-sidebar-empty">No secrets yet.</div>
        )}
        <ul className="secret-list">
          {items.map(item => (
            <li
              key={item.path}
              className={item.path === path ? 'active' : ''}
              onClick={() => handleSelectSecret(item)}
            >
              <div className="secret-path">{item.path}</div>
              <div className="secret-meta" style={{ fontSize: '0.75rem' }}>
                <span>{item.app_name || item.app_id}</span>
              </div>
              <div className="secret-meta">
                <span>v{item.version}</span>
                <span>{new Date(item.created_at).toLocaleDateString()}</span>
              </div>
            </li>
          ))}
        </ul>
      </aside>

      <section className="secret-main">
        <h2 style={{ marginTop: 0 }}>Store a new secret</h2>
        <p className="secret-subtitle">
          Compose key/value pairs for your secret. Values stay masked until you explicitly reveal them.
        </p>

        <div className="secret-section">
          <h4>Application</h4>
          <div className="secret-rows">
            <div className="secret-row">
              <input
                className="secret-row-key"
                placeholder="App ID (required)"
                value={appId}
                onChange={e => setAppId(e.target.value)}
              />
              <input
                className="secret-row-value"
                placeholder="App name (optional)"
                value={appName}
                onChange={e => setAppName(e.target.value)}
              />
            </div>
          </div>
        </div>

        <div className="secret-section">
          <label className="form-label">Secret path</label>
          <input value={path} onChange={e => setPath(e.target.value)} placeholder="e.g. service/api" />
        </div>

        <div className="secret-section">
          <h4>Secret key/value pairs</h4>
          <div className="secret-rows">
            {rows.map((row, index) => (
              <div key={`row-${index}`} className="secret-row">
                <input
                  className="secret-row-key"
                  placeholder="key (e.g. username)"
                  value={row.key}
                  onChange={e => handleRowChange(index, 'key', e.target.value)}
                />
                <input
                  className="secret-row-value"
                  placeholder="value"
                  type={row.masked ? 'password' : 'text'}
                  value={row.value}
                  onChange={e => handleRowChange(index, 'value', e.target.value)}
                />
                <button
                  type="button"
                  className="ghost"
                  onClick={() => toggleMask(index)}
                >
                  {row.masked ? 'Show' : 'Hide'}
                </button>
                <button
                  type="button"
                  className="ghost"
                  onClick={() => removeRow(index)}
                  disabled={rows.length === 1}
                >
                  Remove
                </button>
              </div>
            ))}
          </div>
          <button type="button" className="link-btn" onClick={addRow}>
            + Add row
          </button>
        </div>

        <div className="secret-actions">
          <button type="button" onClick={writeSecret} disabled={saving}>
            {saving ? 'Saving…' : 'Save secret'}
          </button>
          <div className="secret-version-input">
            <input
              value={version}
              onChange={e => setVersion(e.target.value)}
              placeholder="version (optional)"
            />
            <button
              type="button"
              onClick={() => fetchSecret({ targetPath: path, targetVersion: version || null })}
              disabled={previewLoading || !path.trim()}
            >
              {previewLoading ? 'Loading…' : 'Load secret'}
            </button>
          </div>
        </div>

        {err && <div className="text-danger">{err}</div>}

        {out && (
          <div className="secret-preview">
            <div className="secret-preview-header">
              <div>
                <h4>Preview</h4>
                <div className="secret-preview-meta">
                  <span>App: {out.app_name || out.app_id}</span>
                  <span>Path: {out.path}</span>
                  <span>Version: v{out.version}</span>
                  <span>{new Date(out.created_at).toLocaleString()}</span>
                </div>
              </div>
              <div className="secret-preview-actions">
                <button type="button" onClick={() => setShowPreview(v => !v)}>
                  {showPreview ? 'Hide values' : 'Reveal values'}
                </button>
                <button type="button" className="ghost" onClick={loadIntoEditor}>
                  Load into editor
                </button>
              </div>
            </div>
            <ul>
              {Object.entries(out.value || {}).map(([key, value]) => (
                <li key={key}>
                  <span className="secret-preview-key">{key}</span>
                  <span className="secret-preview-value">
                    {showPreview ? String(value) : MASK}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>
    </div>
  )
}
