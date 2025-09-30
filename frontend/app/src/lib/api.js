const base = import.meta.env.VITE_API_BASE_URL || '';

export async function loginRequest({ email, password }) {
  const r = await fetch(base + '/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });

  if (!r.ok) {
    const t = await r.text().catch(() => '');
    throw new Error(`${r.status} ${t || r.statusText}`);
  }

  const data = await r.json();

  const user = {
    id: data.user.id,
    username: data.user.username,
    email: data.user.email,
    roles: data.user.roles || [],
    lastLogin: data.user.last_login
  };

  return { token: data.access_token || '', user };
}
