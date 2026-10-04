import { useCallback, useEffect, useState } from 'react';

export interface ApiDataState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  retry: () => void;
}

export interface ApiDataOptions {
  /** Silent-refresh interval in ms (live demo mode). Refreshes never blank the page. */
  pollMs?: number;
}

/**
 * Lightweight fetch-state hook for service-layer calls.
 * Refetches when `deps` change, when `retry` is called, and (optionally) on a
 * polling interval so live backend incidents appear without a manual refresh.
 */
export function useApiData<T>(
  fetcher: () => Promise<T>,
  deps: unknown[] = [],
  options?: ApiDataOptions,
): ApiDataState<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const pollMs = options?.pollMs;

  useEffect(() => {
    let cancelled = false;

    const load = (silent: boolean) => {
      if (!silent) {
        setLoading(true);
        setError(null);
      }
      fetcher()
        .then((result) => {
          if (!cancelled) {
            setData(result);
            setLoading(false);
            setError(null);
          }
        })
        .catch((err: unknown) => {
          if (!cancelled) {
            setError(err instanceof Error ? err.message : 'Something went wrong');
            setLoading(false);
          }
        });
    };

    load(false);
    if (pollMs && pollMs > 0) {
      const interval = window.setInterval(() => load(true), pollMs);
      return () => {
        cancelled = true;
        window.clearInterval(interval);
      };
    }
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, attempt, pollMs]);

  const retry = useCallback(() => setAttempt((n) => n + 1), []);

  return { data, loading, error, retry };
}
