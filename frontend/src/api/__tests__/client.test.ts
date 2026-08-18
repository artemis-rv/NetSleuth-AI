import { describe, it, expect, vi, beforeEach } from 'vitest';
import { apiClient } from '../client';
import { ApiError } from '../errors';
import { tokenStore } from '../../auth/auth-store';

describe('apiClient', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    tokenStore.clear();
  });

  it('attaches Bearer token when token is present in store', async () => {
    tokenStore.set('test-jwt-token');
    const mockFetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    );

    await apiClient('/api/v1/cases');

    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/cases'),
      expect.objectContaining({
        headers: expect.any(Headers),
      })
    );

    const headers = mockFetch.mock.calls[0][1]?.headers as Headers;
    expect(headers.get('Authorization')).toBe('Bearer test-jwt-token');
  });

  it('serializes query parameters properly', async () => {
    const mockFetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify({ items: [], total: 0, page: 1, page_size: 10 }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    );

    await apiClient('/api/v1/cases', {
      params: { page: '2', page_size: '10', status: 'OPEN' },
    });

    const calledUrl = mockFetch.mock.calls[0][0] as string;
    expect(calledUrl).toContain('page=2');
    expect(calledUrl).toContain('page_size=10');
    expect(calledUrl).toContain('status=OPEN');
  });

  it('parses structured API error envelope', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          error: {
            code: 'CASE_ACCESS_DENIED',
            message: 'User does not have access to case',
            request_id: 'req-12345',
          },
        }),
        {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        }
      )
    );

    await expect(apiClient('/api/v1/cases/denied-id')).rejects.toThrow(ApiError);
  });

  it('normalizes network connection errors to ApiError with code NETWORK_ERROR', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(new Error('Failed to fetch'));

    try {
      await apiClient('/api/v1/cases');
      expect.unreachable('Should have thrown');
    } catch (err: any) {
      expect(err).toBeInstanceOf(ApiError);
      expect(err.code).toBe('NETWORK_ERROR');
      expect(err.status).toBe(0);
    }
  });
});
