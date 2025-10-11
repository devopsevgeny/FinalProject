import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { MDBBtn, MDBContainer, MDBCard, MDBCardBody, MDBInput } from 'mdb-react-ui-kit'
import { loginRequest } from '../lib/api'
import { saveSession } from '../lib/session'

export default function Login() {
  const nav = useNavigate()
  const [username, setUsername] = useState('')
  const [pwd, setPwd] = useState('')
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)

  async function onSubmit(e) {
    e.preventDefault()
    setErr('')
    setLoading(true)
    try {
      const { token, user } = await loginRequest({ username, password: pwd })
      if (!token) throw new Error('Empty token')
      saveSession({ token, user })
      nav('/whoami', { replace: true })    // ← вот переход
    } catch (e) {
      setErr(e?.message || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  const disabled = !username || !pwd || loading

  return (
    <MDBContainer fluid className="auth-wrapper">
      <MDBCard className="auth-card">
        <MDBCardBody className="p-4">
          <h3 className="text-center mb-3">Sign in</h3>
          <form onSubmit={onSubmit} className="d-grid gap-3">
            <MDBInput
              label="Username"
              id="username"
              type="text"
              size="lg"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              autoComplete="username"
            />
            <MDBInput
              label="Password"
              id="password"
              type="password"
              size="lg"
              value={pwd}
              onChange={(e) => setPwd(e.target.value)}
              required
              autoComplete="current-password"
            />
            {err && <div className="error-msg">{err}</div>}
            <MDBBtn type="submit" color="primary" disabled={disabled}>
              {loading ? 'Signing in…' : 'Login'}
            </MDBBtn>
          </form>
        </MDBCardBody>
      </MDBCard>
    </MDBContainer>
  )
}
