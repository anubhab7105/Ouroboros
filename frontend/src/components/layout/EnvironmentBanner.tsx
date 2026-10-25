import {
  ENVIRONMENT,
  ENVIRONMENT_BANNER_CLASSES,
  ENVIRONMENT_LABEL,
  SHOW_ENVIRONMENT_BANNER,
  SHOW_SYNTHETIC_BANNER,
} from '@/lib/environment';

/**
 * A standing band naming the environment.
 *
 * Investigation platforms get cloned for training and for demos, and the
 * screens are identical. An analyst who closes a case in the staging copy has
 * done nothing at all, and will not find out for days. The banner is
 * deliberately hard to miss, and its presence always means "this is not the
 * real thing".
 *
 * It appears everywhere except an unflagged production deployment, and the
 * synthetic-data flag forces it on: a deployment that forgot to configure the
 * banner should over-warn rather than under-warn, because the cost of a
 * spurious band is mild and the cost of a missing one is somebody acting on
 * generated output as though it described a real account.
 */
export function EnvironmentBanner() {
  if (!SHOW_ENVIRONMENT_BANNER) return null;

  return (
    <div
      role="note"
      className={`flex items-center justify-center gap-2 px-4 py-1 text-2xs font-semibold uppercase tracking-wider ${ENVIRONMENT_BANNER_CLASSES[ENVIRONMENT]}`}
    >
      <span aria-hidden="true">●</span>
      <span>{ENVIRONMENT_LABEL}</span>
      <span className="font-normal normal-case tracking-normal opacity-90">
        {SHOW_SYNTHETIC_BANNER
          ? '— synthetic data. Nothing here is a finding about a real person or account.'
          : '— actions here do not affect production records'}
      </span>
    </div>
  );
}
