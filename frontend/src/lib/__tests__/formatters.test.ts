import { describe, expect, it } from 'vitest';

import { formatAmount, formatCompactAmount, formatConfidence, formatScore } from '../amounts';
import { formatDateTime, formatDuration } from '../dates';
import { sanitiseFilename } from '../download';
import {
  formatBoolean,
  formatCellValue,
  formatEvidenceReference,
  humaniseEnum,
  initials,
  joinList,
  truncateId,
} from '../formatters';

describe('amount formatting', () => {
  it('groups and fixes to two decimals', () => {
    expect(formatAmount(1234567.5)).toBe('12,34,567.50');
  });

  it('appends the currency code rather than guessing a symbol', () => {
    // The platform ingests whatever the source system sends, so a guessed
    // symbol would be wrong for some deployments.
    expect(formatAmount(1000, 'inr')).toBe('1,000.00 INR');
  });

  it('renders an em dash for missing and non-finite values', () => {
    expect(formatAmount(null)).toBe('—');
    expect(formatAmount(Number.NaN)).toBe('—');
    expect(formatAmount(Number.POSITIVE_INFINITY)).toBe('—');
  });

  it('compacts large values for axes', () => {
    expect(formatCompactAmount(1_500_000)).toBe('1.5M');
    expect(formatCompactAmount(2_400)).toBe('2.4K');
  });
});

describe('score and confidence formatting', () => {
  it('shows one decimal for a score', () => {
    expect(formatScore(87.349)).toBe('87.3');
  });

  it('renders a dash for a null confidence rather than 0.000', () => {
    // A deterministic correlation carries no confidence by design; showing
    // zero would read as "no confidence", the opposite of the truth.
    expect(formatConfidence(null)).toBe('—');
    expect(formatConfidence(0.4567)).toBe('0.457');
  });
});

describe('date formatting', () => {
  it('labels absolute timestamps as UTC', () => {
    expect(formatDateTime('2026-03-01T10:30:00Z')).toBe('2026-03-01 10:30 UTC');
  });

  it('returns a dash for an unparseable value', () => {
    expect(formatDateTime('not a date')).toBe('—');
    expect(formatDateTime(null)).toBe('—');
  });

  it('formats durations readably', () => {
    expect(formatDuration(0.4)).toBe('<1s');
    expect(formatDuration(42.5)).toBe('42.5s');
    expect(formatDuration(135)).toBe('2m 15s');
  });
});

describe('identifier formatting', () => {
  it('truncates in the middle so ids sharing a prefix stay distinguishable', () => {
    const a = truncateId('acc_8f3b1c2d4e5f6a7b8c9d');
    const b = truncateId('acc_8f3b1c2d4e5fZZZZZZZZ');
    expect(a).not.toBe(b);
    expect(a).toContain('…');
  });

  it('leaves a short id untouched', () => {
    expect(truncateId('acc_1')).toBe('acc_1');
  });

  it('formats an evidence reference with its human label', () => {
    expect(formatEvidenceReference('TRANSACTION:txn_000123')).toBe('Transaction txn_0001…');
  });

  it('returns the raw value for a malformed reference', () => {
    expect(formatEvidenceReference('garbage')).toBe('garbage');
  });
});

describe('text helpers', () => {
  it('humanises enum tokens', () => {
    expect(humaniseEnum('UNDER_INVESTIGATION')).toBe('Under investigation');
    expect(humaniseEnum(null)).toBe('—');
  });

  it('joins lists like a sentence', () => {
    expect(joinList(['a'])).toBe('a');
    expect(joinList(['a', 'b'])).toBe('a and b');
    expect(joinList(['a', 'b', 'c'])).toBe('a, b and c');
    expect(joinList([null, undefined, ''])).toBe('—');
  });

  it('renders booleans as words, not ticks', () => {
    expect(formatBoolean(true)).toBe('yes');
    expect(formatBoolean(null)).toBe('—');
  });

  it('never throws on an unknown cell value', () => {
    expect(formatCellValue({ a: 1 })).toBe('{"a":1}');
    expect(formatCellValue([1, 2])).toBe('1, 2');
    expect(formatCellValue(undefined)).toBe('—');
  });

  it('derives initials', () => {
    expect(initials('ada.lovelace')).toBe('AL');
    expect(initials('ada')).toBe('AD');
    expect(initials(null)).toBe('?');
  });
});

describe('download filename sanitising', () => {
  it('strips directory components', () => {
    expect(sanitiseFilename('../../etc/passwd')).toBe('passwd');
  });

  it('removes characters that break on Windows', () => {
    expect(sanitiseFilename('bad"name\nhere.pdf')).toBe('bad-name-here.pdf');
  });

  it('falls back when nothing usable remains', () => {
    expect(sanitiseFilename('///')).toBe('muleguard-download');
  });
});
