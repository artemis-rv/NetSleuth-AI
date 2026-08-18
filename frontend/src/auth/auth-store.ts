/**
 * Abstract interface for Authentication Token Storage.
 * Keeps the storage strategy (e.g. localStorage, cookies, session)
 * decoupled from the rest of the application.
 */
export interface AuthTokenStore {
  get(): string | null;
  set(token: string): void;
  clear(): void;
  hasToken(): boolean;
}

// Initial FE-0 implementation using localStorage.
// Can be swapped for a secure cookie-based implementation later
// without affecting consumers.
class LocalStorageTokenStore implements AuthTokenStore {
  private readonly TOKEN_KEY = 'netsleuth_auth_token';

  get(): string | null {
    return localStorage.getItem(this.TOKEN_KEY);
  }

  set(token: string): void {
    localStorage.setItem(this.TOKEN_KEY, token);
  }

  clear(): void {
    localStorage.removeItem(this.TOKEN_KEY);
  }

  hasToken(): boolean {
    return !!this.get();
  }
}

export const tokenStore: AuthTokenStore = new LocalStorageTokenStore();
