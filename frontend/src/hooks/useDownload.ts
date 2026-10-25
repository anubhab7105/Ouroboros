import { useCallback, useState } from 'react';

import { downloadFromApi } from '@/lib/download';
import { toFriendlyError, type FriendlyError } from '@/lib/errorMapper';

/**
 * Download state for a report or export button.
 *
 * Reports take seconds to render, so the button needs a pending state or the
 * user clicks it repeatedly. `isDownloading` also guards against a second
 * concurrent request for the same file.
 */
export function useDownload() {
  const [isDownloading, setIsDownloading] = useState(false);
  const [error, setError] = useState<FriendlyError | null>(null);
  const [lastFilename, setLastFilename] = useState<string | null>(null);

  const download = useCallback(
    async (url: string, fallbackFilename: string, params?: Record<string, unknown>) => {
      if (isDownloading) return false;

      setIsDownloading(true);
      setError(null);

      try {
        const result = await downloadFromApi(url, fallbackFilename, params);
        setLastFilename(result.filename);
        return true;
      } catch (caught) {
        setError(toFriendlyError(caught));
        return false;
      } finally {
        setIsDownloading(false);
      }
    },
    [isDownloading],
  );

  return { download, isDownloading, error, lastFilename, clearError: () => setError(null) };
}
