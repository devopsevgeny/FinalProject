export function saveSession({ token, user }) {
  localStorage.setItem('token', token || '');
  localStorage.setItem('user', JSON.stringify(user || {}));
}

export function getToken() {
  return localStorage.getItem('token') || '';
}

export function getUser() {
  try { return JSON.parse(localStorage.getItem('user') || '{}'); }
  catch { return {}; }
}

export function clearSession() {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
}
