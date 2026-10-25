import { differenceInCalendarDays, format, formatDistanceToNowStrict, isValid, parseISO } from 'date-fns';

/**
 * Date formatting.
 *
 * Absolute timestamps are rendered with an explicit `UTC` suffix. The backend
 * is UTC end to end, and an unlabelled timestamp in a financial investigation
 * is a reconciliation hazard: an analyst in one timezone reading a colleague's
 * note needs to know which clock it refers to.
 *
 * Relative times ("3 days ago") are for queue age, where the comparison
 * matters more than the instant. They are always paired with the absolute
 * value in a tooltip.
 */

const DATE_FORMAT = 'yyyy-MM-dd';
const DATE_TIME_FORMAT = 'yyyy-MM-dd HH:mm';
const DATE_TIME_SECONDS_FORMAT = 'yyyy-MM-dd HH:mm:ss';

function toDate(value: string | Date | null | undefined): Date | null {
  if (!value) return null;
  const parsed = typeof value === 'string' ? parseISO(value) : value;
  return isValid(parsed) ? parsed : null;
}

/** Shift an instant so `date-fns`' local formatter renders UTC wall-clock time. */
function toUtcDate(date: Date): Date {
  return new Date(date.getTime() + date.getTimezoneOffset() * 60000);
}

export function formatDate(value: string | Date | null | undefined): string {
  const date = toDate(value);
  return date ? format(toUtcDate(date), DATE_FORMAT) : '—';
}

/** Absolute timestamp with an explicit UTC marker. */
export function formatDateTime(
  value: string | Date | null | undefined,
  options: { seconds?: boolean } = {},
): string {
  const date = toDate(value);
  if (!date) return '—';

  const pattern = options.seconds ? DATE_TIME_SECONDS_FORMAT : DATE_TIME_FORMAT;
  return `${format(toUtcDate(date), pattern)} UTC`;
}

/** Relative age, e.g. "3 days ago". Always pair with the absolute value. */
export function formatRelative(value: string | Date | null | undefined): string {
  const date = toDate(value);
  if (!date) return '—';

  try {
    return `${formatDistanceToNowStrict(date)} ago`;
  } catch {
    return formatDateTime(value);
  }
}

/** Whole days since a timestamp, for queue-age columns. */
export function daysSince(value: string | Date | null | undefined): number | null {
  const date = toDate(value);
  if (!date) return null;
  return Math.max(0, differenceInCalendarDays(new Date(), date));
}

/** Format a trend bucket label according to the granularity the server used. */
export function formatBucketLabel(
  value: string,
  granularity: 'hour' | 'day' | 'week' | 'month',
): string {
  const date = toDate(value);
  if (!date) return value;

  switch (granularity) {
    case 'hour':
      return format(toUtcDate(date), 'MMM d HH:mm');
    case 'day':
      return format(toUtcDate(date), 'MMM d');
    case 'week':
      return `w/c ${format(toUtcDate(date), 'MMM d')}`;
    case 'month':
      return format(toUtcDate(date), 'MMM yyyy');
    default:
      return format(toUtcDate(date), DATE_FORMAT);
  }
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return '—';
  if (seconds < 1) return '<1s';
  if (seconds < 60) return `${seconds.toFixed(1)}s`;

  const minutes = Math.floor(seconds / 60);
  const remainder = Math.round(seconds % 60);

  if (minutes < 60) return `${minutes}m ${remainder}s`;

  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}

/** `YYYY-MM-DD` for a date input, or empty string. */
export function toDateInputValue(value: string | Date | null | undefined): string {
  const date = toDate(value);
  return date ? format(toUtcDate(date), DATE_FORMAT) : '';
}

/** A date input's value as an ISO instant, or undefined. */
export function fromDateInputValue(value: string, endOfDay = false): string | undefined {
  if (!value) return undefined;
  const date = parseISO(endOfDay ? `${value}T23:59:59.999Z` : `${value}T00:00:00.000Z`);
  return isValid(date) ? date.toISOString() : undefined;
}

export function isFuture(value: string | Date | null | undefined): boolean {
  const date = toDate(value);
  return date ? date.getTime() > Date.now() : false;
}
