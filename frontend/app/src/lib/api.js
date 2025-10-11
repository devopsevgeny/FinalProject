// frontend/app/src/lib/api.js

// Support both env variable names for convenience:
// - VITE_API_BASE (recommended)
// - VITE_API_BASE_URL (legacy)
const base =
  import.meta.env.VITE_API_BASE ||
  import.meta.env.VITE_API_BASE_URL ||
  ''; // e.g. "/api" when using Vite proxy, or "http://localhost:8080" without proxy

/**
 * Logs in against /auth/login. Your backend expects { username, password }.
 * If your form collects an email, we map it to the username field.
 * After login, fetch /whoami to build a user object (since /auth/login only returns the access_token).
 */
export async function loginRequest({ email, username, password }) {
  const body = {
    username: username || email, // backend expects "username"
    password
  };

  const r = await fetch(base + '/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });

  if (!r.ok) {
    const t = await r.text().catch(() => '');
    throw new Error(`${r.status} ${t || r.statusText}`);
  }

  const data = await r.json();
  const token = data.access_token || '';

  // Backend does not return the user payload from /auth/login,
  // so we call /whoami with the bearer token to derive a user object.
  let user = null;
  if (token) {
    const w = await fetch(base + '/whoami', {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (w.ok) {
      const who = await w.json();
      user = {
        id: who?.sub || who?.user_id || null,
        username: who?.username || who?.name || null,
        email: who?.email || null,
        roles: who?.roles || who?.permissions || [],
        lastLogin: who?.last_login || null
      };
    }
  }

  return { token, user };
}
