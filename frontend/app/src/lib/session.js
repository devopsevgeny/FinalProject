const AUTH_KEY = 'auth';

function parseAuth(value) {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value);
    return typeof parsed === 'object' && parsed !== null ? parsed : null;
  } catch {
    return null;
  }
}

function readLegacySession() {
  const legacyToken = localStorage.getItem('token') || '';
  const legacyUserRaw = localStorage.getItem('user');
  let legacyUser = null;

  if (legacyUserRaw) {
    try { legacyUser = JSON.parse(legacyUserRaw); }
    catch { legacyUser = null; }
  }

  if (!legacyToken && !legacyUserRaw) return null;

  const session = { token: legacyToken, user: legacyUser };
  localStorage.setItem(AUTH_KEY, JSON.stringify(session));
  localStorage.removeItem('token');
  localStorage.removeItem('user');
  return session;
}

export function getSession() {
  const current = parseAuth(localStorage.getItem(AUTH_KEY));
  if (current) return current;
  return readLegacySession() || { token: '', user: null };
}

export function saveSession({ token, user }) {
  const session = {
    token: token || '',
    user: user ?? null
  };
  localStorage.setItem(AUTH_KEY, JSON.stringify(session));
  localStorage.removeItem('token');
  localStorage.removeItem('user');
}

export function getToken() {
  return getSession().token || '';
}

export function getUser() {
  return getSession().user || null;
}

export function clearSession() {
  localStorage.removeItem(AUTH_KEY);
  localStorage.removeItem('token');
  localStorage.removeItem('user');
}
