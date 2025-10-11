import { createSlice, createAsyncThunk } from '@reduxjs/toolkit'
import { api } from '../api.js'
import jwtDecode from 'jwt-decode'

export const login = createAsyncThunk('auth/login', async ({ username, password }, { rejectWithValue }) => {
  try {
    const { data } = await api.post('/auth/login', { username, password })
    return data?.access_token
  } catch (e) {
    return rejectWithValue(e?.response?.data?.detail || 'Login failed')
  }
})

const initialState = { token: null, claims: null, status: 'idle', error: null }

const slice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    logout(s) { s.token=null; s.claims=null; s.status='idle'; s.error=null },
    setToken(s,a) { s.token=a.payload; s.claims = a.payload ? safeDecode(a.payload) : null }
  },
  extraReducers: b => {
    b.addCase(login.pending,   s=>{ s.status='loading'; s.error=null })
     .addCase(login.fulfilled, (s,a)=>{ s.status='succeeded'; s.token=a.payload; s.claims=safeDecode(a.payload) })
     .addCase(login.rejected,  (s,a)=>{ s.status='failed'; s.error=a.payload || 'Login failed' })
  }
})

function safeDecode(t){ try { return jwtDecode(t) } catch { return null } }

export const { logout, setToken } = slice.actions
export default slice.reducer
