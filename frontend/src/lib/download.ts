import { getBlob } from './apiClient';

/**
 * Trigger a file download in the browser.
 *
 * The object URL is revoked on the next tick rather than immediately: Safari
 * cancels the download if the URL is revoked in the same task that clicks the
 * link.
 *
 * The filename comes from the server's `Content-Disposition` when present,
 * because the backend builds a sanitised name following the report naming
 * convention. The `fallbackFilename` is only used when the server did not set
 * one, and it is sanitised here before use.
 */

/** Strip anything that would make a filename unsafe on Windows or POSIX. */
export function sanitiseFilename(name: string, fallback = 'muleguard-download'): string {
  const base = name.split(/[\\/]/).pop() ?? '';
  const cleaned = base
    .replace(/[^A-Za-z0-9._-]+/g, '-')
    .replace(/-{2,}/g, '-')
    .replace(/^[.-]+|[.-]+$/g, '');

  return cleaned.length > 0 ? cleaned.slice(0, 180) : fallback;
}

export function saveBlob(blob: Blob, filename: string): void {
  const safe = sanitiseFilename(filename);
  const url = URL.createObjectURL(blob);

  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = safe;
  anchor.rel = 'noopener';
  anchor.style.display = 'none';

  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);

  // Deferred: revoking synchronously cancels the download in Safari.
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

export async function downloadFromApi(
  url: string,
  fallbackFilename: string,
  params?: Record<string, unknown>,
): Promise<{ filename: string; bytes: number }> {
  const { blob, filename } = await getBlob(url, { params });
  const resolved = sanitiseFilename(filename ?? fallbackFilename);

  saveBlob(blob, resolved);
  return { filename: resolved, bytes: blob.size };
}

/** Save a JSON object as a download, for a JSON report export. */
export function saveJson(data: unknown, filename: string): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: 'application/json;charset=utf-8',
  });
  saveBlob(blob, filename.endsWith('.json') ? filename : `${filename}.json`);
}

/**
 * Save rows as CSV.
 *
 * Values are quoted and internal quotes doubled. A value starting with
 * `=`, `+`, `-` or `@` is prefixed with an apostrophe, because spreadsheet
 * applications treat those as formulas and a transaction reference beginning
 * with `-` would otherwise execute on open.
 */
export function saveCsv(
  rows: Array<Record<string, unknown>>,
  filename: string,
  columns?: string[],
): void {
  if (rows.length === 0) return;

  const headers = columns ?? Object.keys(rows[0] ?? {});

  const escape = (value: unknown): string => {
    if (value === null || value === undefined) return '';

    let text = typeof value === 'object' ? JSON.stringify(value) : String(value);

    if (/^[=+\-@\t\r]/.test(text)) {
      text = `'${text}`;
    }

    return `"${text.replace(/"/g, '""')}"`;
  };

  const lines = [
    headers.map(escape).join(','),
    ...rows.map((row) => headers.map((header) => escape(row[header])).join(',')),
  ];

  // A BOM makes Excel read the file as UTF-8 rather than the local codepage.
  const blob = new Blob(['﻿', lines.join('\r\n')], {
    type: 'text/csv;charset=utf-8',
  });

  saveBlob(blob, filename.endsWith('.csv') ? filename : `${filename}.csv`);
}
