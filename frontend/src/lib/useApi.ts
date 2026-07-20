'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError } from './api';

export interface UseApiResult<T> {
  data: T | null;
  error: ApiError | null;
  loading: boolean;
  /** True only for the very first load, so polling never flashes a spinner. */
  initialLoading: boolean;
  refetch: () => void;
}

/**
 * Fetch once, optionally poll.
 *
 * Errors are kept as `ApiError` so callers can distinguish "backend offline"
 * from "endpoint not implemented" from a real failure. On a polling refresh the
 * previous data is retained while the new request is in flight.
 */
export function useApi<T>(
  fetcher: () => Promise<T>,
  deps: unknown[] = [],
  pollMs?: number
): UseApiResult<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(true);
  const [initialLoading, setInitialLoading] = useState(true);

  // Keep the latest fetcher without making it a dependency of the effect.
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const mountedRef = useRef(true);
  const [tick, setTick] = useState(0);

  const refetch = useCallback(() => setTick((n) => n + 1), []);

  useEffect(() => {
    mountedRef.current = true;
    let cancelled = false;

    const run = async () => {
      if (!cancelled) setLoading(true);
      try {
        const result = await fetcherRef.current();
        if (cancelled || !mountedRef.current) return;
        setData(result);
        setError(null);
      } catch (err) {
        if (cancelled || !mountedRef.current) return;
        setError(
          err instanceof ApiError
            ? err
            : new ApiError(
                err instanceof Error ? err.message : 'Unknown error',
                0,
                'unknown'
              )
        );
      } finally {
        if (!cancelled && mountedRef.current) {
          setLoading(false);
          setInitialLoading(false);
        }
      }
    };

    run();

    let timer: ReturnType<typeof setInterval> | undefined;
    if (pollMs && pollMs > 0) {
      timer = setInterval(run, pollMs);
    }

    return () => {
      cancelled = true;
      mountedRef.current = false;
      if (timer) clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, pollMs, tick]);

  return { data, error, loading, initialLoading, refetch };
}
