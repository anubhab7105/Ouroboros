/**
 * Money formatting.
 *
 * Amounts are grouped and shown to two decimals, with the currency code rather
 * than a symbol. `₹1,00,000` and `$100,000` differ in both symbol and grouping
 * convention, and this platform handles whatever the source system sends, so a
 * guessed symbol would be wrong somewhere. The explicit code is unambiguous.
 *
 * `formatCompactAmount` is for chart axes and KPI tiles only. A compacted
 * figure must never appear where a reader might transcribe it into a report,
 * because `1.2M` has lost the digits that matter.
 */

const DEFAULT_LOCALE = 'en-IN';

export function formatAmount(
  value: number | null | undefined,
  currency?: string | null,
  options: { locale?: string; decimals?: number } = {},
): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';

  const { locale = DEFAULT_LOCALE, decimals = 2 } = options;
  const formatted = new Intl.NumberFormat(locale, {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  }).format(value);

  return currency ? `${formatted} ${currency.toUpperCase()}` : formatted;
}

/**
 * Abbreviated amount for axes and tiles. Never use where the exact figure
 * matters: the omitted digits are the ones a reader would need.
 */
export function formatCompactAmount(
  value: number | null | undefined,
  currency?: string | null,
): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';

  const absolute = Math.abs(value);
  const units: Array<[number, string]> = [
    [1_000_000_000, 'B'],
    [1_000_000, 'M'],
    [1_000, 'K'],
  ];

  for (const [threshold, suffix] of units) {
    if (absolute >= threshold) {
      const scaled = value / threshold;
      const text = `${scaled.toFixed(scaled >= 100 ? 0 : 1).replace(/\.0$/, '')}${suffix}`;
      return currency ? `${text} ${currency.toUpperCase()}` : text;
    }
  }

  return formatAmount(value, currency, { decimals: 0 });
}

export function formatCount(value: number | null | undefined, locale = DEFAULT_LOCALE): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  return new Intl.NumberFormat(locale).format(value);
}

export function formatPercent(
  value: number | null | undefined,
  options: { decimals?: number; alreadyScaled?: boolean } = {},
): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';

  const { decimals = 1, alreadyScaled = false } = options;
  const scaled = alreadyScaled ? value : value * 100;
  return `${scaled.toFixed(decimals)}%`;
}

/**
 * Format a 0-100 investigative priority score.
 *
 * One decimal: the score is ordinal, and more precision implies a
 * discrimination the fusion does not actually have.
 */
export function formatScore(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  return value.toFixed(1);
}

/**
 * Format a 0-1 confidence.
 *
 * Returns the em dash for null rather than `0.000`, because a deterministic
 * correlation deliberately carries no confidence and showing zero would read
 * as "no confidence" — the opposite of the truth.
 */
export function formatConfidence(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  return value.toFixed(3);
}

export function formatRatio(value: number | null | undefined, decimals = 2): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  return value.toFixed(decimals);
}
