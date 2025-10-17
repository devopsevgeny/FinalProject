const flag = (import.meta.env.VITE_ENABLE_DEBUG_LOGS ?? '').trim().toLowerCase()
const mode = import.meta.env.MODE || 'development'

const enabled = flag === 'true' || (flag !== 'false' && mode !== 'production')

const formatPayload = (payload) => {
  if (payload === undefined) return ''
  if (typeof payload === 'string') return payload
  try {
    return JSON.stringify(payload)
  } catch {
    return String(payload)
  }
}

function emit(level, event, payload) {
  if (!enabled) return
  const ts = new Date().toISOString()
  const prefix = `[ConfMgr][${level.toUpperCase()}][${ts}] ${event}`

  if (payload === undefined) {
    console[level](prefix)
  } else {
    console[level](prefix, payload)
  }
}

export function logInfo(event, payload) {
  emit('info', event, payload)
}

export function logWarn(event, payload) {
  emit('warn', event, payload)
}

export function logError(event, payload) {
  emit('error', event, payload)
}

export function logDebug(event, payload) {
  emit('debug', event, payload)
}

export function logValue(event, value) {
  emit('info', event, formatPayload(value))
}
