'use client';

import { cn } from '@/lib/utils';
import { ApiError, API_BASE } from '@/lib/api';
import { Button } from '@/components/ui/Button';
import {
  Loader2,
  PlugZap,
  ServerCrash,
  Inbox,
  RefreshCw,
  Construction,
} from 'lucide-react';

/* -------------------------------------------------------------------------- */

export function LoadingState({
  label = 'Loading…',
  className,
}: {
  label?: string;
  className?: string;
}) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center gap-3 py-12 text-center',
        className
      )}
    >
      <Loader2 className="h-6 w-6 animate-spin text-accent-blue" />
      <p className="text-xs text-gray-500 font-mono">{label}</p>
    </div>
  );
}

/* -------------------------------------------------------------------------- */

/**
 * Shown when the world model genuinely holds no data. Never used to paper over
 * an error — an unreachable or missing endpoint gets its own state below.
 */
export function EmptyState({
  title = 'No data yet',
  message = 'No events ingested — run a scenario to populate the world model.',
  icon,
  action,
  className,
}: {
  title?: string;
  message?: string;
  icon?: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center gap-3 py-12 px-6 text-center',
        className
      )}
    >
      <div className="p-3 rounded-full bg-surface text-gray-600">
        {icon || <Inbox className="h-6 w-6" />}
      </div>
      <div>
        <p className="text-sm font-medium text-gray-300">{title}</p>
        <p className="text-xs text-gray-500 mt-1 max-w-md">{message}</p>
      </div>
      {action}
    </div>
  );
}

/* -------------------------------------------------------------------------- */

/**
 * The backend is not running / not reachable. Explicitly distinguished from
 * "there is no data", because rendering zeros here would be a lie.
 */
function OfflineState({ error, onRetry }: { error: ApiError; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-12 px-6 text-center">
      <div className="p-3 rounded-full bg-accent-red/10 text-accent-red">
        <PlugZap className="h-6 w-6" />
      </div>
      <div>
        <p className="text-sm font-medium text-accent-red">Backend unreachable</p>
        <p className="text-xs text-gray-400 mt-1 max-w-md">
          Could not connect to the Sentinel API. No data is being displayed
          because none could be retrieved.
        </p>
        <p className="text-[10px] text-gray-600 font-mono mt-2">{API_BASE}</p>
        <p className="text-[10px] text-gray-600 font-mono mt-1">
          Start it with: uvicorn app.main:app --reload --port 8000
        </p>
      </div>
      {onRetry && (
        <Button size="sm" variant="secondary" onClick={onRetry} icon={<RefreshCw className="h-3.5 w-3.5" />}>
          Retry
        </Button>
      )}
    </div>
  );
}

/**
 * The route exists in API_CONTRACT.md but no router is mounted for it yet.
 * This is the honest rendering for the Sentinel route groups that the backend
 * has not built — the page structure is real, the data genuinely is not there.
 */
function NotImplementedState({
  error,
  onRetry,
}: {
  error: ApiError;
  onRetry?: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-12 px-6 text-center">
      <div className="p-3 rounded-full bg-accent-yellow/10 text-accent-yellow">
        <Construction className="h-6 w-6" />
      </div>
      <div>
        <p className="text-sm font-medium text-accent-yellow">
          Endpoint not implemented
        </p>
        <p className="text-xs text-gray-400 mt-1 max-w-md">
          The backend returned 404 for this route. It is specified in
          API_CONTRACT.md but no router is mounted for it yet, so there is no
          data to show. This view will populate as soon as the endpoint lands.
        </p>
        <p className="text-[10px] text-gray-600 font-mono mt-2">
          GET {error.endpoint}
        </p>
      </div>
      {onRetry && (
        <Button size="sm" variant="secondary" onClick={onRetry} icon={<RefreshCw className="h-3.5 w-3.5" />}>
          Retry
        </Button>
      )}
    </div>
  );
}

function GenericErrorState({
  error,
  onRetry,
}: {
  error: ApiError;
  onRetry?: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-12 px-6 text-center">
      <div className="p-3 rounded-full bg-accent-red/10 text-accent-red">
        <ServerCrash className="h-6 w-6" />
      </div>
      <div>
        <p className="text-sm font-medium text-accent-red">
          Request failed{error.status ? ` (HTTP ${error.status})` : ''}
        </p>
        <p className="text-xs text-gray-400 mt-1 max-w-md">{error.message}</p>
        <p className="text-[10px] text-gray-600 font-mono mt-2">{error.endpoint}</p>
      </div>
      {onRetry && (
        <Button size="sm" variant="secondary" onClick={onRetry} icon={<RefreshCw className="h-3.5 w-3.5" />}>
          Retry
        </Button>
      )}
    </div>
  );
}

export function ErrorState({
  error,
  onRetry,
}: {
  error: ApiError;
  onRetry?: () => void;
}) {
  if (error.offline) return <OfflineState error={error} onRetry={onRetry} />;
  if (error.notImplemented)
    return <NotImplementedState error={error} onRetry={onRetry} />;
  return <GenericErrorState error={error} onRetry={onRetry} />;
}

/* -------------------------------------------------------------------------- */

/**
 * Standard async wrapper: spinner on first load, an explicit error state on
 * failure, an empty state when the payload is genuinely empty, content
 * otherwise. Using this everywhere is what stops the UI inventing numbers.
 */
export function AsyncBoundary<T>({
  state,
  children,
  empty,
  isEmpty,
  loadingLabel,
}: {
  state: {
    data: T | null;
    error: ApiError | null;
    initialLoading: boolean;
    refetch: () => void;
  };
  children: (data: T) => React.ReactNode;
  empty?: React.ReactNode;
  isEmpty?: (data: T) => boolean;
  loadingLabel?: string;
}) {
  if (state.initialLoading) return <LoadingState label={loadingLabel} />;
  if (state.error) return <ErrorState error={state.error} onRetry={state.refetch} />;
  if (state.data === null) return <EmptyState />;
  if (isEmpty?.(state.data)) return <>{empty ?? <EmptyState />}</>;
  return <>{children(state.data)}</>;
}

/* -------------------------------------------------------------------------- */

/** Compact inline banner for secondary panels that must not dominate a page. */
export function InlineError({ error }: { error: ApiError }) {
  const text = error.offline
    ? 'Backend unreachable'
    : error.notImplemented
      ? 'Endpoint not implemented'
      : `Failed (HTTP ${error.status})`;

  return (
    <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-accent-red/5 border border-accent-red/20">
      <ServerCrash className="h-3.5 w-3.5 text-accent-red shrink-0" />
      <span className="text-[10px] text-accent-red">{text}</span>
      <span className="text-[10px] text-gray-600 font-mono ml-auto truncate">
        {error.endpoint}
      </span>
    </div>
  );
}
