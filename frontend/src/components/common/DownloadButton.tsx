import { useDownload } from '@/hooks/useDownload';

import { Button, type ButtonProps } from './Button';
import { ErrorState } from './ErrorState';

export interface DownloadButtonProps extends Omit<ButtonProps, 'onClick' | 'isLoading'> {
  url: string;
  filename: string;
  params?: Record<string, unknown>;
  label?: string;
  /** Show the error inline below the button. On by default. */
  showError?: boolean;
}

/**
 * A button that downloads a file from the API.
 *
 * Reports take a few seconds to render, so the pending state is necessary:
 * without it the user clicks again, and a second render starts while the first
 * is still running.
 *
 * Errors render inline rather than as a toast. The common failure is a 503
 * because ReportLab is not installed, and the fix — request JSON instead — is
 * something the user needs to read, not watch disappear.
 */
export function DownloadButton({
  url,
  filename,
  params,
  label = 'Download',
  showError = true,
  variant = 'secondary',
  ...rest
}: DownloadButtonProps) {
  const { download, isDownloading, error } = useDownload();

  return (
    <div className="inline-flex flex-col items-start gap-2">
      <Button
        variant={variant}
        isLoading={isDownloading}
        onClick={() => void download(url, filename, params)}
        {...rest}
      >
        {isDownloading ? 'Preparing…' : label}
      </Button>

      {showError && error ? <ErrorState error={error} compact className="max-w-md" /> : null}
    </div>
  );
}
