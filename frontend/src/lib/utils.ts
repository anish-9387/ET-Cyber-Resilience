import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(date: string) {
  return new Date(date).toLocaleString();
}

export function formatDuration(minutes: number) {
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  const mins = minutes % 60;
  return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
}

export function severityColor(severity: string) {
  const colors: Record<string, string> = {
    critical: 'text-red-500 bg-red-500/10',
    high: 'text-orange-500 bg-orange-500/10',
    medium: 'text-yellow-500 bg-yellow-500/10',
    low: 'text-cyan-500 bg-cyan-500/10',
    info: 'text-blue-500 bg-blue-500/10',
  };
  return colors[severity] || colors.info;
}

export function statusColor(status: string) {
  const colors: Record<string, string> = {
    healthy: 'text-green-500',
    degraded: 'text-yellow-500',
    compromised: 'text-red-500',
    recovering: 'text-cyan-500',
  };
  return colors[status] || 'text-gray-500';
}
