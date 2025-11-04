import { useRef, useState } from 'react'
import { api } from '../api.js'
import { logInfo, logError } from '../lib/logger.js'

const formatSize = (bytes) => {
  if (typeof bytes !== 'number' || Number.isNaN(bytes)) return ''
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let value = bytes
  let unit = 'KB'
  for (let i = 0; i < units.length; i += 1) {
    value /= 1024
    unit = units[i]
    if (value < 1024 || i === units.length - 1) break
  }
  return `${value.toFixed(value < 10 ? 2 : 1)} ${unit}`
}

export default function ConfigPage() {
  const [appId, setAppId] = useState('default')
  const [appName, setAppName] = useState('')
  const [path, setPath] = useState('app/feature-flags')
  const [json, setJson] = useState('{"beta_ui": true, "limit": 50}')
  const [filePayload, setFilePayload] = useState(null)
  const [fileMeta, setFileMeta] = useState(null)
  const [out, setOut] = useState(null)
  const [err, setErr] = useState(null)
  const fileInputRef = useRef(null)

  const triggerUpload = () => {
    fileInputRef.current?.click()
  }

  const clearSelectedFile = () => {
    setFilePayload(null)
    setFileMeta(null)
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  const handleFileUpload = (event) => {
    const file = event.target.files?.[0]
    if (!file) return
    setFilePayload(file)
    setFileMeta({
      name: file.name,
      size: file.size,
      contentType: file.type,
      persisted: false
    })
    setJson('')
    setErr(null)
  }

  const write = async () => {
    setErr(null)
    const trimmedAppId = (appId || '').trim()
    if (!trimmedAppId) {
      setErr('Provide an App ID.')
      return
    }

    // File upload branch
    if (filePayload) {
      logInfo('config.write.request', { appId: trimmedAppId, path, mode: 'file' })
      try {
        const body = new FormData()
        body.append('file', filePayload)
        body.append('app_id', trimmedAppId)
        if (appName?.trim()) body.append('app_name', appName.trim())
        const { data } = await api.post(
          `/config/${encodeURIComponent(path)}/file`,
          body,
          { headers: { 'Content-Type': 'multipart/form-data' } }
        )
        logInfo('config.write.success', { appId: trimmedAppId, path, mode: 'file' })
        setOut(data)
        if (data.app_id) setAppId(data.app_id)
        if (data.app_name) setAppName(data.app_name)
        setFilePayload(null)
        if (fileInputRef.current) fileInputRef.current.value = ''
        setFileMeta({
          name: data.file_name,
          size: data.file_size,
          contentType: data.content_type,
          persisted: true
        })
        setJson('')
        return
      } catch (e) {
        const message = e?.response?.data?.detail || e?.message || 'Upload failed'
        logError('config.write.error', { appId: trimmedAppId, path, message, mode: 'file' })
        setErr(message)
        return
      }
    }

    // JSON branch
    let parsed
    try {
      parsed = JSON.parse(json)
    } catch {
      setErr('Config body must be valid JSON.')
      return
    }

    logInfo('config.write.request', { appId: trimmedAppId, path, mode: 'json' })
    try {
      const body = {
        app_id: trimmedAppId,
        app_name: appName?.trim() || undefined,
        value: parsed
      }
      const { data } = await api.post(`/config/${encodeURIComponent(path)}`, body)
      logInfo('config.write.success', { appId: trimmedAppId, path, mode: 'json' })
      setOut(data)
      if (data.app_id) setAppId(data.app_id)
      if (data.app_name) setAppName(data.app_name)
      setFileMeta(null)
    } catch (e) {
      const message = e?.response?.data?.detail || e?.message || 'Write failed'
      logError('config.write.error', { appId: trimmedAppId, path, message, mode: 'json' })
      setErr(message)
    }
  }

  const read = async () => {
    setErr(null)
    const trimmedAppId = (appId || '').trim()
    if (!trimmedAppId) {
      setErr('Provide an App ID.')
      return
    }
    logInfo('config.read.request', { appId: trimmedAppId, path })
    try {
      const { data } = await api.get(
        `/config/${encodeURIComponent(path)}?appId=${encodeURIComponent(trimmedAppId)}`
      )
      logInfo('config.read.success', { appId: trimmedAppId, path })
      setOut(data)
      if (data.app_id) setAppId(data.app_id)
      if (data.app_name) setAppName(data.app_name)

      if (data.data_type === 'file') {
        setJson('')
        setFilePayload(null)
        setFileMeta({
          name: data.file_name,
          size: data.file_size,
          contentType: data.content_type,
          persisted: true
        })
      } else {
        setJson(JSON.stringify(data.value ?? {}, null, 2))
        setFilePayload(null)
        setFileMeta(null)
      }
    } catch (e) {
      const message = e?.response?.data?.detail || 'Read failed'
      logError('config.read.error', { appId: trimmedAppId, path, message })
      setErr(message)
    }
  }

  const download = async () => {
    setErr(null)
    const trimmedAppId = (appId || '').trim()
    if (!trimmedAppId) {
      setErr('Provide an App ID.')
      return
    }
    logInfo('config.download.request', { appId: trimmedAppId, path })
    try {
      const url = `/config/${encodeURIComponent(path)}/file?appId=${encodeURIComponent(trimmedAppId)}`
      const response = await api.get(url, { responseType: 'blob' })
      logInfo('config.download.success', { appId: trimmedAppId, path })
      const disposition = response.headers?.['content-disposition'] || ''
      const match = disposition.match(/filename="?([^"]+)"?/i)
      const filename = match?.[1] || fileMeta?.name || 'config.bin'
      const blob = new Blob([response.data], {
        type: response.headers?.['content-type'] || 'application/octet-stream'
      })
      const link = document.createElement('a')
      link.href = URL.createObjectURL(blob)
      link.download = filename
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      URL.revokeObjectURL(link.href)
    } catch (e) {
      const message = e?.response?.data?.detail || 'Download failed'
      logError('config.download.error', { appId: trimmedAppId, path, message })
      setErr(message)
    }
  }

  const disableJsonInput = Boolean(filePayload)

  return (
    <div className="d-grid gap-3" style={{ maxWidth: 880 }}>
      <h3>Config</h3>
      <div className="d-flex gap-3">
        <input
          value={appId}
          onChange={e => setAppId(e.target.value)}
          placeholder="App ID (required)"
        />
        <input
          value={appName}
          onChange={e => setAppName(e.target.value)}
          placeholder="App name (optional)"
        />
      </div>
      <input
        value={path}
        onChange={e => setPath(e.target.value)}
        placeholder="path (e.g. app/feature-flags)"
      />
      <div className="d-flex gap-3 flex-wrap">
        <button onClick={write}>Save config</button>
        <button onClick={read}>Load config</button>
        <button type="button" onClick={triggerUpload}>Upload file</button>
        {(filePayload || fileMeta) && (
          <button type="button" onClick={clearSelectedFile}>
            Clear file
          </button>
        )}
        {fileMeta?.persisted && (
          <button type="button" onClick={download}>
            Download file
          </button>
        )}
        <input
          ref={fileInputRef}
          type="file"
          style={{ display: 'none' }}
          onChange={handleFileUpload}
        />
      </div>
      {fileMeta && (
        <div style={{ color: '#475569', fontSize: '0.85rem' }}>
          {fileMeta.persisted ? 'Stored file:' : 'Selected file:'}{' '}
          <strong>{fileMeta.name || 'unnamed'}</strong>
          {fileMeta.size != null && ` · ${formatSize(fileMeta.size)}`}
          {fileMeta.contentType && ` · ${fileMeta.contentType}`}
        </div>
      )}
      <textarea
        rows={10}
        value={json}
        onChange={e => setJson(e.target.value)}
        placeholder={disableJsonInput ? 'Upload a file or clear selection to edit JSON' : undefined}
        disabled={disableJsonInput}
      />
      {err && <div className="text-danger">{err}</div>}
      {out && <pre>{JSON.stringify(out, null, 2)}</pre>}
    </div>
  )
}
