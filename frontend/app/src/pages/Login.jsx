import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  MDBBtn,
  MDBContainer,
  MDBCard,
  MDBCardBody,
  MDBInput
} from 'mdb-react-ui-kit';

import { loginRequest } from '../lib/api';
import { saveSession, getSession } from '../lib/session';
import { logInfo, logError } from '../lib/logger.js';

export default function Login() {
  const nav = useNavigate();
  const [username, setUsername] = useState('');
  const [pwd, setPwd] = useState('');
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(false);

  const goToApp = useCallback(() => {
    nav('/app', { replace: true });
    // HashRouter fallback (or any case where nav does not update location synchronously)
    setTimeout(() => {
      if (!location.hash.includes('/app') && location.pathname !== '/app') {
        location.hash = '#/app';
      }
    }, 0);
  }, [nav]);

  // Если уже залогинен — сразу на главную страницу
  useEffect(() => {
    const s = getSession();
    if (s?.token) {
      logInfo('auth.session.exists', 'Redirecting to /app');
      goToApp();
    }
  }, [goToApp]);

  async function onSubmit(e) {
    e.preventDefault();
    setErr('');
    setLoading(true);
    try {
      logInfo('auth.login.submit', { username });
      const { token, user } = await loginRequest({ username, password: pwd });
      if (!token) throw new Error('Empty token');
      saveSession({ token, user });
      logInfo('auth.login.success', { username, roles: user?.roles });
      goToApp();
    } catch (e) {
      logError('auth.login.fail', { username, message: e?.message });
      setErr(e?.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  }

  const disabled = !username || !pwd || loading;

  return (
    <MDBContainer fluid className="auth-wrapper">
      <MDBCard className="auth-card">
        <MDBCardBody className="p-4">
          <div className="text-center mb-4">
            <h3 className="mb-1">ConSecMaster</h3>
            <div style={{ color: '#6c757d' }}>Secrets &amp; Config Manager</div>
          </div>
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

            {err && (
              <div className="error-msg" role="alert" style={{ color: '#ffccd5' }}>
                {err}
              </div>
            )}

            <MDBBtn type="submit" color="primary" disabled={disabled}>
              {loading ? 'Signing in…' : 'Login'}
            </MDBBtn>
          </form>
        </MDBCardBody>
      </MDBCard>
    </MDBContainer>
  );
}
