import axios from 'axios'
import { API_BASE, API_KEY } from './lib/env.js'
import { getToken } from './lib/session.js'
import { logDebug, logError } from './lib/logger.js'

const generateActorId = () => {
  if (globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') {
    return globalThis.crypto.randomUUID()
  }
  const rnd = () => Math.floor((1 + Math.random()) * 0x10000).toString(16).substring(1)
  return `${rnd()}${rnd()}-${rnd()}-${rnd()}-${rnd()}-${rnd()}${rnd()}${rnd()}`
}

let tokenGetter = () => getToken()
export const setTokenGetter = fn => { tokenGetter = typeof fn === 'function' ? fn : getToken }

export const api = axios.create({
  baseURL: API_BASE,
  withCredentials: true
})

api.interceptors.request.use(config => {
  if (API_KEY) {
    config.headers['X-API-Key'] = API_KEY
  } else {
    const t = tokenGetter()
    if (t) config.headers.Authorization = `Bearer ${t}`
  }

  const method = (config.method || 'get').toLowerCase()
  if (['post', 'put', 'patch', 'delete'].includes(method)) {
    let actorId = localStorage.getItem('confmgr_actor_id')
    if (!actorId) {
      actorId = generateActorId()
      localStorage.setItem('confmgr_actor_id', actorId)
    }
    const headers = config.headers || (config.headers = {})
    headers['X-Actor-Id'] = actorId
    headers['X-Actor-Subject'] = 'frontend-ui'
    const isFormData = typeof FormData !== 'undefined' && config.data instanceof FormData
    if (!isFormData) {
      headers['Content-Type'] = headers['Content-Type'] || 'application/json'
    } else if (headers['Content-Type']) {
      delete headers['Content-Type']
    }
  }

  logDebug('api.request', { method, url: config.url })
  return config
})

api.interceptors.response.use(
  response => {
    logDebug('api.response', { status: response.status, url: response.config?.url })
    return response
  },
  error => {
    const status = error?.response?.status
    const url = error?.config?.url
    logError('api.response.error', { status, url, message: error?.message })
    throw error
  }
)
