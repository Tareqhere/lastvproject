/**
 * API client module.
 * Typed functions for all backend endpoints.
 * Uses credentials: 'include' for cookie-based auth.
 */
import type { Report, AuthState, AnalysisResult } from './types';

const API_BASE = '/api';

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    credentials: 'include', // Send cookies for auth
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  const data = await res.json();

  if (!res.ok) {
    throw new Error(data.error || data.message || `Request failed with status ${res.status}`);
  }

  return data as T;
}

// ── Auth ────────────────────────────────────

export async function signup(email: string, password: string) {
  return request<{ message: string; user: { id: string; email: string } }>('/signup', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
}

export async function login(email: string, password: string) {
  return request<{ message: string; user: { id: string; email: string } }>('/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
}

export async function logout() {
  return request<{ message: string }>('/logout', { method: 'POST' });
}

export async function getMe(): Promise<AuthState> {
  return request<AuthState>('/me');
}

export async function deleteAccount() {
  return request<{ message: string }>('/account', { method: 'DELETE' });
}

// ── Analysis ────────────────────────────────

export async function analyze(inputType: string, content: string) {
  return request<{ id: string; inputType: string; contentPreview: string; result: AnalysisResult; createdAt: string }>(
    '/analyze',
    {
      method: 'POST',
      body: JSON.stringify({ inputType, content }),
    }
  );
}

// ── Reports ─────────────────────────────────

export async function getReports() {
  return request<{ reports: Report[] }>('/reports');
}

export async function getReport(id: string) {
  return request<Report>(`/reports/${id}`);
}

export async function deleteReport(id: string) {
  return request<{ message: string }>(`/reports/${id}`, { method: 'DELETE' });
}
