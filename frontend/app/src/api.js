import axios from 'axios'
import { API_BASE, API_KEY } from './lib/env.js'

let tokenGetter = () => null
export const setTokenGetter = fn => { tokenGetter = fn }

export const api = axios.create({
  baseURL: API_BASE,
  withCredentials: true
})

api.interceptors.request.use(config => {
  // auth: либо API Key, либо Bearer
  if (API_KEY) {
    config.headers['X-API-Key'] = API_KEY
  } else {
    const t = tokenGetter()
    if (t) config.headers.Authorization = `Bearer ${t}`
  }

  // audit заголовки для write
  const m = (config.method || 'get').toLowerCase()
  if (['post','put','patch','delete'].includes(m)) {
    let actorId = localStorage.getItem('confmgr_actor_id')
    if (!actorId && crypto?.randomUUID) {
      actorId = crypto.randomUUID()
      localStorage.setItem('confmgr_actor_id', actorId)
    }
    config.headers['X-Actor-Id'] = actorId || 'frontend'
    config.headers['X-Actor-Subject'] = 'frontend-ui'
    config.headers['Content-Type'] = config.headers['Content-Type'] || 'application/json'
  }
  return config
})
