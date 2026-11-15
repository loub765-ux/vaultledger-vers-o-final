/**
 * VaultLedger Auth + API Client
 * Uses server at same origin (or localhost:5500)
 */

const API_BASE = (() => {
  if (typeof location !== 'undefined' && location.protocol.startsWith('http')) {
    return location.origin;
  }
  return 'http://localhost:5500';
})();

const TOKEN_KEY = 'vl_token';
const USER_KEY = 'vl_user';

export function getToken() {
  return localStorage.getItem(TOKEN_KEY) || '';
}

export function getCurrentUser() {
  try {
    const raw = localStorage.getItem(USER_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function setSession(token, user) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function clearSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

async function api(path, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };
  const token = getToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  let data = null;
  const text = await res.text();
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { error: text || 'Erro de resposta' };
  }

  if (!res.ok) {
    const err = new Error((data && data.error) || `Erro ${res.status}`);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

export async function registerUser(name, email, password) {
  const data = await api('/api/register', {
    method: 'POST',
    body: { name, email, password },
  });
  setSession(data.token, data.user);
  return data.user;
}

export async function loginUser(email, password) {
  const data = await api('/api/login', {
    method: 'POST',
    body: { email, password },
  });
  setSession(data.token, data.user);
  return data.user;
}

export async function logout() {
  try {
    await api('/api/logout', { method: 'POST', body: {} });
  } catch (_) {}
  clearSession();
  window.location.href = 'login.html';
}

export async function fetchMe() {
  const user = await api('/api/me');
  localStorage.setItem(USER_KEY, JSON.stringify(user));
  return user;
}

export async function requireAuth() {
  const token = getToken();
  if (!token) {
    window.location.href = 'login.html';
    return null;
  }
  try {
    return await fetchMe();
  } catch {
    clearSession();
    window.location.href = 'login.html';
    return null;
  }
}

export async function deleteAccount() {
  await api('/api/account', { method: 'DELETE' });
  clearSession();
}

// ── Data APIs ──

export async function getTransactions() {
  return api('/api/transactions');
}

export async function createTransaction(tx) {
  return api('/api/transactions', { method: 'POST', body: tx });
}

export async function deleteTransaction(id) {
  return api(`/api/transactions/${id}`, { method: 'DELETE' });
}

export async function getGoals() {
  return api('/api/goals');
}

export async function createGoal(goal) {
  return api('/api/goals', { method: 'POST', body: goal });
}

export async function updateGoal(id, data) {
  return api(`/api/goals/${id}`, { method: 'PUT', body: data });
}

export async function deleteGoal(id) {
  return api(`/api/goals/${id}`, { method: 'DELETE' });
}

export async function getAgenda() {
  return api('/api/agenda');
}

export async function createAgendaItem(item) {
  return api('/api/agenda', { method: 'POST', body: item });
}

export async function deleteAgendaItem(id) {
  return api(`/api/agenda/${id}`, { method: 'DELETE' });
}

export async function getSettings() {
  return api('/api/settings');
}

export async function saveSettings(settings) {
  return api('/api/settings', { method: 'PUT', body: settings });
}

// Expose globally for non-module scripts
if (typeof window !== 'undefined') {
  window.VLAuth = {
    getToken,
    getCurrentUser,
    clearSession,
    registerUser,
    loginUser,
    logout,
    fetchMe,
    requireAuth,
    deleteAccount,
    getTransactions,
    createTransaction,
    deleteTransaction,
    getGoals,
    createGoal,
    updateGoal,
    deleteGoal,
    getAgenda,
    createAgendaItem,
    deleteAgendaItem,
    getSettings,
    saveSettings,
    api,
    API_BASE,
  };
}
