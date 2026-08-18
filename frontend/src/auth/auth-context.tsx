import { createContext, useContext, useState, useEffect } from 'react';
import type { ReactNode } from 'react';
import type { User } from './auth-types';
import { tokenStore } from './auth-store';
import { apiClient } from '../api/client';
import { ApiError } from '../api/errors';

type AuthState = 'authenticating' | 'authenticated' | 'unauthenticated' | 'logging_out';

interface AuthContextValue {
  state: AuthState;
  user: User | null;
  login: (token: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>('authenticating');
  const [user, setUser] = useState<User | null>(null);

  useEffect(() => {
    async function loadUser() {
      if (!tokenStore.hasToken()) {
        setState('unauthenticated');
        return;
      }
      try {
        const userData = await apiClient<User>('/api/v1/auth/me');
        setUser(userData);
        setState('authenticated');
      } catch (err) {
        // If 401, clear token and state
        if (err instanceof ApiError && err.status === 401) {
          tokenStore.clear();
          setState('unauthenticated');
        } else {
          // Keep unauthenticated if backend fails entirely, or could be a different handling
          setState('unauthenticated');
        }
      }
    }
    loadUser();
  }, []);

  const login = async (token: string) => {
    setState('authenticating');
    tokenStore.set(token);
    try {
      const userData = await apiClient<User>('/api/v1/auth/me');
      setUser(userData);
      setState('authenticated');
    } catch (err) {
      tokenStore.clear();
      setState('unauthenticated');
      throw err;
    }
  };

  const logout = async () => {
    setState('logging_out');
    try {
      // Best effort backend logout
      await apiClient('/api/v1/auth/logout', { method: 'POST' });
    } catch (err) {
      console.warn('Backend logout failed', err);
    } finally {
      tokenStore.clear();
      setUser(null);
      setState('unauthenticated');
    }
  };

  return (
    <AuthContext.Provider value={{ state, user, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}
