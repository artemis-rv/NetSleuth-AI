import { tokenStore } from '../auth/auth-store';
import { ApiError } from './errors';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8001';

interface FetchOptions extends RequestInit {
  params?: Record<string, string>;
}

export async function apiClient<T>(endpoint: string, options: FetchOptions = {}): Promise<T> {
  const { params, ...customConfig } = options;
  const token = tokenStore.get();
  
  const headers = new Headers(customConfig.headers);
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  
  if (customConfig.body && !(customConfig.body instanceof FormData)) {
    if (!headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }
  }

  const config: RequestInit = {
    ...customConfig,
    headers,
  };

  const url = new URL(`${BASE_URL}${endpoint}`);
  if (params) {
    Object.keys(params).forEach(key => url.searchParams.append(key, params[key]));
  }

  let response: Response;
  try {
    response = await fetch(url.toString(), config);
  } catch (error: any) {
    throw new ApiError(error.message, 0, 'NETWORK_ERROR');
  }

  let data;
  try {
    data = await response.json();
  } catch {
    data = null;
  }

  if (!response.ok) {
    // Dispatch a global event so AuthContext can force logout on token expiration
    if (response.status === 401) {
      window.dispatchEvent(new CustomEvent('auth:unauthorized'));
    }
    
    // Note: The UI layer (AuthContext/Router) will handle state transitions and redirects
    // for 401 (Unauthenticated) and 403 (Forbidden). The client just normalizes the error.
    if (data && data.error) {
      throw new ApiError(
        data.error.message || 'API request failed',
        response.status,
        data.error.code || 'API_ERROR',
        data.error.request_id,
        data.error.details
      );
    }
    throw new ApiError('An unexpected error occurred', response.status, 'UNKNOWN_ERROR');
  }

  return data as T;
}
