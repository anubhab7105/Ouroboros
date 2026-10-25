/**
 * Runtime environment resolution.
 *
 * Reads the `VITE_`-prefixed variables once and exposes typed accessors, so a
 * component never parses `import.meta.env` itself and a missing variable has
 * one defined fallback rather than several.
 *
 * The variable names are the ones `docker-compose.yml` passes as build args —
 * `VITE_ENVIRONMENT_LABEL`, `VITE_SHOW_SYNTHETIC_BANNER` and the rest. That
 * file is the deployment contract, so it decides the names; where a more
 * conventional alternative exists (`VITE_ENVIRONMENT`) it is accepted as well,
 * because a developer running Vite by hand will reach for it.
 *
 * Nothing secret belongs in here: every value is readable by anyone who loads
 * the bundle.
 */

export type EnvironmentName = 'local' | 'development' | 'staging' | 'production';

const DEFAULT_API_BASE = '/api/v1';
const DEFAULT_TIMEOUT_MS = 30_000;

function readString(value: string | undefined, fallback: string): string {
  const trimmed = (value ?? '').trim();
  return trimmed.length > 0 ? trimmed : fallback;
}

function readInt(value: string | undefined, fallback: number): number {
  const parsed = Number.parseInt((value ?? '').trim(), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

/**
 * Read a boolean flag.
 *
 * Defaults to **on** for the safety banners: a deployment that forgot to set
 * the variable should over-warn rather than under-warn, since the cost of a
 * spurious banner is mild and the cost of a missing one is somebody acting on
 * synthetic output as though it were real.
 */
function readBool(value: string | undefined, fallback: boolean): boolean {
  const trimmed = (value ?? '').trim().toLowerCase();
  if (trimmed.length === 0) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(trimmed);
}

export const APP_NAME = readString(import.meta.env.VITE_APP_NAME, 'MuleGuard');

/**
 * Base URL for API calls. Relative by default so the browser stays on one
 * origin, which keeps CORS and cookie behaviour identical in development
 * (Vite proxy) and production (nginx).
 */
export const API_BASE_URL = readString(import.meta.env.VITE_API_BASE_URL, DEFAULT_API_BASE);

export const API_TIMEOUT_MS = readInt(import.meta.env.VITE_API_TIMEOUT_MS, DEFAULT_TIMEOUT_MS);

export const APP_VERSION = readString(import.meta.env.VITE_APP_VERSION, '0.0.0-dev');

export const DEFAULT_CURRENCY = readString(import.meta.env.VITE_DEFAULT_CURRENCY, 'INR');

export const DEFAULT_LOCALE = readString(import.meta.env.VITE_DEFAULT_LOCALE, 'en-IN');

/** The timezone label shown beside timestamps. The API is UTC end to end. */
export const TIMEZONE_LABEL = readString(import.meta.env.VITE_TIMEZONE, 'UTC');

/**
 * The environment label.
 *
 * `VITE_ENVIRONMENT_LABEL` is free text from compose ("DOCKER SYNTHETIC
 * DEMO"), which is exactly what should appear in the banner. The narrower
 * `VITE_ENVIRONMENT` drives styling, and the label falls back to it.
 */
export const ENVIRONMENT: EnvironmentName = (() => {
  const raw = readString(import.meta.env.VITE_ENVIRONMENT, '').toLowerCase();
  const known: EnvironmentName[] = ['local', 'development', 'staging', 'production'];
  if ((known as string[]).includes(raw)) return raw as EnvironmentName;

  // Infer from the free-text label when only that was set.
  const label = readString(import.meta.env.VITE_ENVIRONMENT_LABEL, '').toLowerCase();
  const inferred = known.find((name) => label.includes(name));

  return inferred ?? 'local';
})();

export const IS_PRODUCTION = ENVIRONMENT === 'production';

export const ENVIRONMENT_LABELS: Record<EnvironmentName, string> = {
  local: 'Local development',
  development: 'Development',
  staging: 'Staging',
  production: 'Production',
};

/** What the banner says: the deployment's own words where it supplied them. */
export const ENVIRONMENT_LABEL = readString(
  import.meta.env.VITE_ENVIRONMENT_LABEL,
  ENVIRONMENT_LABELS[ENVIRONMENT],
);

/**
 * Whether to show the environment banner.
 *
 * On everywhere except production by default, and forced on whenever the
 * deployment says its data is synthetic. The point is that nobody mistakes a
 * copy for the real thing while acting on an alert.
 */
export const SHOW_SYNTHETIC_BANNER = readBool(
  import.meta.env.VITE_SHOW_SYNTHETIC_BANNER,
  true,
);

export const SHOW_ENVIRONMENT_BANNER = SHOW_SYNTHETIC_BANNER || ENVIRONMENT !== 'production';

/**
 * Whether to print the score's meaning wherever a score is shown out of
 * context. Default on: a score without its semantics is the single easiest
 * thing to misread in this application.
 */
export const SHOW_SCORE_DISCLAIMER = readBool(
  import.meta.env.VITE_SHOW_SCORE_DISCLAIMER,
  true,
);

/** Whether to show the platform's stated limitations in the interface. */
export const SHOW_LIMITATIONS = readBool(import.meta.env.VITE_SHOW_LIMITATIONS, true);

/**
 * Banner styling per environment. Staging is the loudest because it is the one
 * that looks most like production and is most often confused with it.
 */
export const ENVIRONMENT_BANNER_CLASSES: Record<EnvironmentName, string> = {
  local: 'bg-ink-700 text-ink-50',
  development: 'bg-accent-700 text-white',
  staging: 'bg-state-warning text-white',
  production: 'bg-ink-900 text-ink-100',
};

export function getEnvironmentInfo() {
  return {
    appName: APP_NAME,
    environment: ENVIRONMENT,
    label: ENVIRONMENT_LABEL,
    version: APP_VERSION,
    apiBaseUrl: API_BASE_URL,
    timeoutMs: API_TIMEOUT_MS,
    currency: DEFAULT_CURRENCY,
    locale: DEFAULT_LOCALE,
    timezone: TIMEZONE_LABEL,
    isProduction: IS_PRODUCTION,
    showSyntheticBanner: SHOW_SYNTHETIC_BANNER,
    showScoreDisclaimer: SHOW_SCORE_DISCLAIMER,
    showLimitations: SHOW_LIMITATIONS,
  };
}
