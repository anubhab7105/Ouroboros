/**
 * Evidence types, mirroring `EvidenceType` in `app/models.py`.
 *
 * Evidence lives on two parents with slightly different shapes: alert
 * evidence (`AlertEvidence` in `./alert`) and case evidence (`CaseEvidence` in
 * `./case`). Only case evidence can be removed, which is why only that shape
 * carries `is_active`.
 */

export type EvidenceType =
  | 'ACCOUNT'
  | 'TRANSACTION'
  | 'COMPLAINT'
  | 'ALERT'
  | 'GRAPH_PATH'
  | 'MODEL_ASSESSMENT'
  | 'ENTITY_LINK';

export const EVIDENCE_TYPE_LABELS: Record<string, string> = {
  ACCOUNT: 'Account',
  TRANSACTION: 'Transaction',
  COMPLAINT: 'Complaint',
  ALERT: 'Alert',
  GRAPH_PATH: 'Network path',
  MODEL_ASSESSMENT: 'Risk assessment',
  ENTITY_LINK: 'Shared identifier',
};

/**
 * What each kind of evidence can and cannot establish.
 *
 * Shown where evidence is attached, because the distinction decides what a
 * report may claim. A transaction is a record of a transfer; a network path is
 * a shape in aggregated edges and is not a tracing of particular funds.
 */
export const EVIDENCE_TYPE_MEANING: Record<string, string> = {
  ACCOUNT: 'The account record as held, including its source-system status.',
  TRANSACTION: 'A single transfer as recorded. Only completed transfers are fund movement.',
  COMPLAINT: 'A complaint as filed. The allegations in it are the complainant’s, not a finding.',
  ALERT: 'A risk finding raised by the platform, with the rules that fired.',
  GRAPH_PATH:
    'A path through aggregated account-to-account edges. It shows a shape, not that the same funds traversed it.',
  MODEL_ASSESSMENT:
    'A score and its component breakdown at one point in time. An investigative priority, not a probability of guilt.',
  ENTITY_LINK:
    'A shared identifier such as a device or UPI handle. Sharing one suggests a connection; it does not prove common control.',
};

/** One line in a report's evidence index. */
export interface EvidenceIndexEntry {
  reference: string;
  evidence_type: string;
  evidence_id: string;
  label: string;
  /** Which report sections cite this item. */
  cited_in: string[];
  /** False when the referenced record could not be loaded at render time. */
  resolved?: boolean | null;
}
