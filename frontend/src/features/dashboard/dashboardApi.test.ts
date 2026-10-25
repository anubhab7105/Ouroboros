import { describe, expect, it } from 'vitest';

import { MAX_DASHBOARD_WINDOW_DAYS, WINDOW_DAY_OPTIONS } from '@/lib/constants';

import { windowFromDays } from './dashboardApi';

describe('dashboard date windows', () => {
  it('caps offered and URL-provided windows at the configured daily bucket maximum', () => {
    expect(WINDOW_DAY_OPTIONS.at(-1)).toBe(MAX_DASHBOARD_WINDOW_DAYS);
    expect(WINDOW_DAY_OPTIONS.every((days) => days <= MAX_DASHBOARD_WINDOW_DAYS)).toBe(true);
  });

  it.each([7, 30, MAX_DASHBOARD_WINDOW_DAYS])(
    'spans exactly %i UTC calendar dates near a UTC day boundary',
    (days) => {
      const range = windowFromDays(days, new Date('2026-10-24T00:00:01.000Z'));
      const firstDate = new Date(range.date_from);
      const lastDate = new Date(range.date_to);
      const expectedStart = new Date(
        Date.UTC(
          lastDate.getUTCFullYear(),
          lastDate.getUTCMonth(),
          lastDate.getUTCDate() - days + 1,
        ),
      );
      const bucketCount =
        (Date.UTC(lastDate.getUTCFullYear(), lastDate.getUTCMonth(), lastDate.getUTCDate()) -
          Date.UTC(firstDate.getUTCFullYear(), firstDate.getUTCMonth(), firstDate.getUTCDate())) /
          (24 * 60 * 60 * 1000) +
        1;

      expect(firstDate.toISOString()).toBe(expectedStart.toISOString());
      expect(lastDate.toISOString()).toBe('2026-10-24T00:00:01.000Z');
      expect(bucketCount).toBe(days);
    },
  );
});
