import { Badge } from '@/components/common/Badge';
import { ENTITY_TYPE_TOKENS, RISK_BAND_TOKENS } from '@/lib/constants';
import { humaniseField } from '@/lib/formatters';

/** Shape per node kind, mirroring the Cytoscape stylesheet. */
const SHAPES: Array<{ kind: string; label: string; path: string; meaning: string }> = [
  {
    kind: 'account',
    label: 'Account',
    path: 'M8 2a6 6 0 1 0 0 12A6 6 0 0 0 8 2z',
    meaning: 'Coloured by the band its score falls in; hollow when never assessed.',
  },
  {
    kind: 'transaction',
    label: 'Transaction',
    path: 'M8 1l7 7-7 7-7-7z',
    meaning: 'A recorded transfer between two accounts.',
  },
  {
    kind: 'entity',
    label: 'Identifier',
    path: 'M4 2h8l4 6-4 6H4L0 8z',
    meaning: 'A shared device, UPI handle, phone or address hash.',
  },
  {
    kind: 'complaint',
    label: 'Complaint',
    path: 'M2 3h12v10H2z',
    meaning: 'A cybercrime complaint as filed.',
  },
  {
    kind: 'alert',
    label: 'Alert',
    path: 'M8 1l7 13H1z',
    meaning: 'A risk finding raised by the platform.',
  },
  {
    kind: 'assessment',
    label: 'Assessment',
    path: 'M2 4h12v8H2z',
    meaning: 'A persisted score with its component breakdown.',
  },
];

const KIND_COLOURS: Record<string, string> = {
  account: '#546175',
  transaction: '#2f7d95',
  entity: '#5b4b8a',
  complaint: '#8a6d1f',
  alert: '#b3541e',
  assessment: '#1f6f50',
};

/**
 * What the canvas is showing.
 *
 * A legend is not optional on a heterogeneous graph: without one, a diamond
 * and a hexagon are two unexplained dots, and an investigator will guess.
 * Three things it is careful to state:
 *
 * - **Shape means kind, colour means risk.** Using colour for both would
 *   leave neither readable.
 * - **A dashed edge is an inference**, not a transfer. This is the single most
 *   consequential mark on the canvas, so it is explained in words rather than
 *   only shown.
 * - **Hollow means never assessed**, which is not the same as a low score.
 */
export function GraphLegend() {
  return (
    <div className="space-y-4 text-2xs">
      <div>
        <h3 className="mb-1.5 font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
          Node kinds
        </h3>
        <ul className="space-y-1.5">
          {SHAPES.map((shape) => (
            <li key={shape.kind} className="flex items-start gap-2">
              <svg
                viewBox="0 0 16 16"
                className="mt-0.5 h-3.5 w-3.5 shrink-0"
                aria-hidden="true"
                fill={KIND_COLOURS[shape.kind]}
              >
                <path d={shape.path} />
              </svg>
              <span className="min-w-0">
                <span className="font-medium text-ink-800 dark:text-ink-100">{shape.label}</span>
                <span className="block text-ink-600 dark:text-ink-300">{shape.meaning}</span>
              </span>
            </li>
          ))}
        </ul>
      </div>

      <div>
        <h3 className="mb-1.5 font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
          Account colour
        </h3>
        <ul className="space-y-1">
          {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((band) => (
            <li key={band} className="flex items-center gap-2">
              <span
                aria-hidden="true"
                className="h-2.5 w-2.5 shrink-0 rounded-full"
                style={{ backgroundColor: RISK_BAND_TOKENS[band].hex }}
              />
              <span className="text-ink-800 dark:text-ink-100">
                {RISK_BAND_TOKENS[band].label}
              </span>
              <span className="text-ink-500 dark:text-ink-400">
                {RISK_BAND_TOKENS[band].description}
              </span>
            </li>
          ))}
          <li className="flex items-center gap-2">
            <span
              aria-hidden="true"
              className="h-2.5 w-2.5 shrink-0 rounded-full border border-dashed border-ink-400"
            />
            <span className="text-ink-800 dark:text-ink-100">Never assessed</span>
            <span className="text-ink-500 dark:text-ink-400">
              Drawn hollow. Not a low score — the absence of one.
            </span>
          </li>
        </ul>

        <p className="mt-1.5 text-ink-500 dark:text-ink-400">
          Node size follows the score, so the eye lands on the accounts worth looking at first.
          The colour is derived from the score using the same cut-points the server uses; the
          authoritative band is the one on the account's assessment.
        </p>
      </div>

      <div>
        <h3 className="mb-1.5 font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
          Edges
        </h3>
        <ul className="space-y-1.5">
          <li className="flex items-center gap-2">
            <svg viewBox="0 0 32 8" className="h-2 w-8 shrink-0" aria-hidden="true">
              <line x1="0" y1="4" x2="32" y2="4" stroke="currentColor" strokeWidth="2" />
            </svg>
            <span className="min-w-0">
              <span className="font-medium text-ink-800 dark:text-ink-100">Solid: recorded</span>
              <span className="block text-ink-600 dark:text-ink-300">
                A transfer that is in the ledger. Thickness follows the amount.
              </span>
            </span>
          </li>
          <li className="flex items-center gap-2">
            <svg viewBox="0 0 32 8" className="h-2 w-8 shrink-0" aria-hidden="true">
              <line
                x1="0"
                y1="4"
                x2="32"
                y2="4"
                stroke="currentColor"
                strokeWidth="2"
                strokeDasharray="5 3"
              />
            </svg>
            <span className="min-w-0">
              <span className="font-medium text-ink-800 dark:text-ink-100">Dashed: inferred</span>
              <span className="block text-ink-600 dark:text-ink-300">
                A relation the platform derived — a shared identifier, or a complaint correlation.
                It suggests a connection and does not establish one.
              </span>
            </span>
          </li>
        </ul>
      </div>

      <div>
        <h3 className="mb-1.5 font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
          Identifier strength
        </h3>
        <ul className="flex flex-wrap gap-1.5">
          {Object.entries(ENTITY_TYPE_TOKENS)
            .sort((a, b) => b[1].strength - a[1].strength)
            .map(([type, token]) => (
              <li key={type}>
                <Badge accentColor={token.hex} title={token.description}>
                  {humaniseField(token.label)}
                </Badge>
              </li>
            ))}
        </ul>
        <p className="mt-1.5 text-ink-500 dark:text-ink-400">
          Strongest first. Sharing a device suggests more than sharing an IP, which many people do
          through one network. None of them proves common control.
        </p>
      </div>
    </div>
  );
}
