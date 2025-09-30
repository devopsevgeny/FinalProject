import React, { useState } from 'react';
import {
  MDBBtn,
  MDBContainer,
  MDBRow,
  MDBCol,
  MDBCard,
  MDBCardBody,
  MDBInput
} from 'mdb-react-ui-kit';

import { loginRequest } from './lib/api';
import { saveSession } from './lib/session';

export default function App() {
  // Local state for form and error
  const [email, setEmail] = useState('');
  const [pwd, setPwd] = useState('');
  const [err, setErr] = useState('');

  // Call backend /auth/login and store session
  async function onLogin() {
    setErr('');
    try {
      const { token, user } = await loginRequest({ email, password: pwd });
      saveSession({ token, user });
      alert(`Logged in as ${user.username || user.email}`);
      // later: navigate to Management page
    } catch (e) {
      console.error(e);
      setErr(String(e));
    }
  }

  return (
    <MDBContainer fluid>
      <MDBRow
        className="d-flex justify-content-center align-items-center"
        style={{ minHeight: '100vh' }}
      >
        <MDBCol col="12">
          <MDBCard className="bg-dark text-white my-5 mx-auto" style={{ borderRadius: '1rem', maxWidth: '400px' }}>
            <MDBCardBody className="p-5 d-flex flex-column align-items-center mx-auto w-100">
              <h2 className="fw-bold mb-2 text-uppercase">Login</h2>
              <p className="text-white-50 mb-3">Please enter your email and password</p>

              <MDBInput
                wrapperClass="mb-3 mx-5 w-100"
                labelClass="text-white"
                label="Email address"
                id="email"
                type="email"
                size="lg"
                value={email}
                onChange={e => setEmail(e.target.value)}
              />
              <MDBInput
                wrapperClass="mb-3 mx-5 w-100"
                labelClass="text-white"
                label="Password"
                id="password"
                type="password"
                size="lg"
                value={pwd}
                onChange={e => setPwd(e.target.value)}
              />

              {err && <div className="text-danger mb-3" style={{ textAlign: 'center' }}>{err}</div>}

              <MDBBtn outline className="mx-2 px-5" color="white" size="lg" onClick={onLogin}>
                Login
              </MDBBtn>

              <div className="mt-4">
                <p className="mb-0">
                  Don&apos;t have an account? <a href="#!" className="text-white-50 fw-bold">Sign Up</a>
                </p>
              </div>
            </MDBCardBody>
          </MDBCard>
        </MDBCol>
      </MDBRow>
    </MDBContainer>
  );
}
