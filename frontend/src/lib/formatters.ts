import type { EvidenceType } from '@/types/evidence';
import { EVIDENCE_TYPE_LABELS } from '@/types/evidence';

/**
 * Text formatting for labels, identifiers and enum tokens.
 *
 * Identifiers are *truncated in the middle*, not the end. Account ids in this
 * system share long prefixes, so `acc_8f3b…` truncated at the end makes two
 * different accounts look identical. Keeping both ends preserves the part a
 * reader uses to tell them apart.
 */

export { formatAmount, formatCompactAmount, formatConfidence, formatCount, formatPercent, formatRatio, formatScore } from './amounts';
export { daysSince, formatBucketLabel, formatDate, formatDateTime, formatDuration, formatRelative } from './dates';

/** `SOME_ENUM_VALUE` to `Some enum value`. */
export function humaniseEnum(value: string | null | undefined): string {
  if (!value) return '—';

  const text = String(value).replace(/[_-]+/g, ' ').trim().toLowerCase();
  if (!text) return '—';

  return text.charAt(0).toUpperCase() + text.slice(1);
}

/** `snake_case_name` to `Snake case name`, for table headers. */
export function humaniseField(value: string | null | undefined): string {
  return humaniseEnum(value);
}

/**
 * Truncate an identifier in the middle, keeping both ends.
 *
 * Truncating at the end would collapse ids that share a prefix into the same
 * string, which is exactly the mistake a reader must not be able to make.
 */
export function truncateId(value: string | null | undefined, keep = 6): string {
  if (!value) return '—';

  const text = String(value);
  if (text.length <= keep * 2 + 1) return text;

  return `${text.slice(0, keep)}…${text.slice(-keep)}`;
}

export function formatEvidenceReference(reference: string | null | undefined): string {
  if (!reference) return '—';

  const [type, id] = String(reference).split(':');
  if (!type || !id) return String(reference);

  const label = EVIDENCE_TYPE_LABELS[type as EvidenceType] ?? humaniseEnum(type);
  return `${label} ${truncateText(id, 9)}`;
}

export function pluralise(count: number, singular: string, plural?: string): string {
  const word = count === 1 ? singular : (plural ?? `${singular}s`);
  return `${count} ${word}`;
}

/** Join a list the way a sentence would: "a, b and c". */
export function joinList(values: Array<string | null | undefined>, conjunction = 'and'): string {
  const items = values.filter((v): v is string => Boolean(v && String(v).trim()));

  if (items.length === 0) return '—';
  if (items.length === 1) return items[0]!;
  if (items.length === 2) return `${items[0]} ${conjunction} ${items[1]}`;

  return `${items.slice(0, -1).join(', ')} ${conjunction} ${items[items.length - 1]}`;
}

export function truncateText(value: string | null | undefined, maxLength = 120): string {
  if (!value) return '';

  const text = String(value).trim();
  if (text.length <= maxLength) return text;

  return `${text.slice(0, maxLength - 1).trimEnd()}…`;
}

/** Initials for an avatar, from a username or full name. */
export function initials(value: string | null | undefined): string {
  if (!value) return '?';

  const parts = String(value).trim().split(/[\s._-]+/).filter(Boolean);
  if (parts.length === 0) return '?';
  if (parts.length === 1) return parts[0]!.slice(0, 2).toUpperCase();

  return `${parts[0]![0]}${parts[parts.length - 1]![0]}`.toUpperCase();
}

/**
 * Render a boolean for a table cell.
 *
 * "yes"/"no" rather than a tick: a tick with no label is ambiguous for a
 * screen reader and for anyone scanning a dense column.
 */
export function formatBoolean(value: boolean | null | undefined): string {
  if (value === null || value === undefined) return '—';
  return value ? 'yes' : 'no';
}

/** Render an unknown JSON cell value without ever throwing. */
export function formatCellValue(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'boolean') return formatBoolean(value);
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : '—';
  if (typeof value === 'string') return value;

  if (Array.isArray(value)) {
    return value.length === 0 ? '—' : value.map((item) => formatCellValue(item)).join(', ');
  }

  if (typeof value === 'object') {
    try {
      return JSON.stringify(value);
    } catch {
      return '[object]';
    }
  }

  return String(value);
}

/** Pick a readable foreground for a hex background, by relative luminance. */
export function contrastText(hex: string): '#ffffff' | '#111620' {
  const normalised = hex.replace('#', '');
  const full =
    normalised.length === 3
      ? normalised.split('').map((c) => c + c).join('')
      : normalised;

  const r = Number.parseInt(full.slice(0, 2), 16) / 255;
  const g = Number.parseInt(full.slice(2, 4), 16) / 255;
  const b = Number.parseInt(full.slice(4, 6), 16) / 255;

  const channel = (c: number) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
  const luminance = 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);

  return luminance > 0.45 ? '#111620' : '#ffffff';
}
