import type { CaseStatus } from '@/types/case';

/**
 * The case state machine, as the API exposes it.
 *
 * The server does **not** return a list of available transitions, so the
 * client has to know the shape of the workflow in order to decide which
 * buttons to offer. That makes this table a duplicate of server-side logic,
 * which is a thing to be honest about: it can drift, and when it does the
 * server is right. Every action is therefore still *attempted* against the
 * API, and a refusal is reported rather than pre-empted — this table only
 * decides what to put on screen.
 *
 * The transitions correspond one-to-one with the endpoints: `start`,
 * `escalate`, `close`, `reopen`. There is no endpoint that sets a status
 * directly, which is why `TRIAGED` is reachable only as a side effect of
 * assignment.
 */

export type CaseAction = 'start' | 'escalate' | 'close' | 'reopen';

export interface TransitionSpec {
  action: CaseAction;
  label: string;
  /** What this does, in the words an investigator would use. */
  description: string;
  /** Statuses from which the action is worth offering. */
  from: CaseStatus[];
  /** The capability name the server checks. */
  capability: string;
  requiresReason: boolean;
  requiresDisposition: boolean;
  /**
   * True when the server refuses the action unless the case has an assignee.
   * `start` carries this: a case in progress that nobody owns counts as
   * active everywhere and has nobody accountable for it.
   */
  requiresAssignee: boolean;
  /** True for an action a reviewer should think twice about. */
  confirm: boolean;
}

export const TRANSITIONS: TransitionSpec[] = [
  {
    action: 'start',
    label: 'Start investigating',
    description:
      'Marks the case as actively being worked. Does nothing to the evidence or the alert it came from.',
    from: ['NEW', 'TRIAGED'],
    capability: 'add_case_note',
    requiresReason: false,
    requiresDisposition: false,
    requiresAssignee: true,
    confirm: false,
  },
  {
    action: 'escalate',
    label: 'Escalate',
    description:
      'Hands the case to a senior investigator. Use it when the decision is above your authority, not merely when the case is difficult.',
    from: ['TRIAGED', 'UNDER_INVESTIGATION'],
    capability: 'add_case_note',
    requiresReason: true,
    requiresDisposition: false,
    requiresAssignee: false,
    confirm: false,
  },
  {
    action: 'close',
    label: 'Close',
    description:
      'Records the outcome and ends the investigation. A reason is required, and the disposition is what anyone reading this case later will see first.',
    from: ['NEW', 'TRIAGED', 'UNDER_INVESTIGATION', 'ESCALATED'],
    capability: 'close_case',
    requiresReason: true,
    requiresDisposition: true,
    requiresAssignee: false,
    confirm: true,
  },
  {
    action: 'reopen',
    label: 'Reopen',
    description:
      'Returns a closed case to investigation. The original disposition stays in the history; reopening adds to the record rather than erasing it.',
    from: ['CLOSED'],
    capability: 'reopen_case',
    requiresReason: true,
    requiresDisposition: false,
    requiresAssignee: false,
    confirm: true,
  },
];

/** The transitions worth offering from a given status. */
export function transitionsFrom(status: string | null | undefined): TransitionSpec[] {
  if (!status) return [];
  return TRANSITIONS.filter((spec) => spec.from.includes(status as CaseStatus));
}

/**
 * The dispositions the server accepts when closing.
 *
 * This is the whole vocabulary, not a convenience subset: the case table's
 * disposition column is declared over the same four values, so anything else
 * is refused.
 */
export const DISPOSITION_OPTIONS = [
  {
    value: 'CONFIRMED_FRAUD',
    label: 'Confirmed fraud',
    help: 'The investigator concluded the activity was fraudulent.',
  },
  {
    value: 'FALSE_POSITIVE',
    label: 'False positive',
    help: 'The activity had an innocent explanation. Worth recording precisely: this is the feedback that improves the rules.',
  },
  {
    value: 'INCONCLUSIVE',
    label: 'Inconclusive',
    help: 'Neither confirmed nor cleared. An honest outcome, and better than forcing one of the other two.',
  },
  {
    value: 'REFERRED',
    label: 'Referred',
    help: 'Passed to another team or authority for action.',
  },
];
