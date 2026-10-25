/// <reference types="vite/client" />

/**
 * Typed environment surface.
 *
 * Declaring these explicitly means a typo in a variable name is a compile
 * error rather than an `undefined` that only shows up at runtime.
 *
 * These names are the ones `docker-compose.yml` passes to the frontend build.
 * That file is the deployment contract; `lib/environment.ts` reads them and
 * nothing else in the application touches `import.meta.env` directly.
 */
interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_API_TIMEOUT_MS?: string;
  readonly VITE_APP_NAME?: string;
  readonly VITE_APP_VERSION?: string;

  /** Free text shown in the banner, e.g. "DOCKER SYNTHETIC DEMO". */
  readonly VITE_ENVIRONMENT_LABEL?: string;
  /** The narrower form, which drives banner styling. */
  readonly VITE_ENVIRONMENT?: 'local' | 'development' | 'staging' | 'production';

  readonly VITE_SHOW_SYNTHETIC_BANNER?: string;
  readonly VITE_SHOW_SCORE_DISCLAIMER?: string;
  readonly VITE_SHOW_LIMITATIONS?: string;

  readonly VITE_DEFAULT_CURRENCY?: string;
  readonly VITE_DEFAULT_LOCALE?: string;
  readonly VITE_TIMEZONE?: string;

  /** Dev only: where the Vite proxy sends /api. */
  readonly VITE_DEV_API_TARGET?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

declare const __APP_BUILD_MODE__: string;
declare const __APP_IS_PRODUCTION__: boolean;
