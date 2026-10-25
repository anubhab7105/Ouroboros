/** Ingestion types, mirroring `app/api/v1/endpoints/ingestion.py`. */

export type IngestEntityType =
  | 'accounts'
  | 'transactions'
  | 'complaints'
  | 'entities'
  | 'entity-links';

export interface IngestionOptions {
  source_system?: string;
  source_batch_id?: string;
  /** Validate and report without writing anything. */
  dry_run?: boolean;
  /** Accept the valid rows and reject the rest, rather than all-or-nothing. */
  allow_partial?: boolean;
  on_duplicate?: 'reject' | 'skip';
}

export interface IngestionRowError {
  /** 1-based index within the submitted batch. */
  row?: number | null;
  field?: string | null;
  code?: string | null;
  message?: string | null;
}

/**
 * The outcome of one batch.
 *
 * Four counters rather than one, because they mean different things:
 * `accepted` was written, `rejected` failed validation, `duplicated` already
 * existed, `skipped` was passed over by the duplicate strategy. A single
 * "imported N" would hide a batch that silently did nothing.
 *
 * `errors` is capped by the server, so a batch with thousands of bad rows
 * returns the first few; `caveats` says when that happened.
 */
export interface BatchIngestResult {
  ok: boolean;
  entity_type: string;
  accepted: number;
  rejected: number;
  duplicated: number;
  skipped: number;
  dry_run: boolean;
  allow_partial: boolean;
  on_duplicate: string;
  source_system?: string | null;
  source_batch_id?: string | null;
  request_id?: string | null;
  errors: IngestionRowError[];
  caveats: string[];
}

/**
 * What ingestion will accept here.
 *
 * `production_like` true with `require_synthetic` true is the configuration
 * that refuses data outright: this platform is built for synthetic data and
 * says so rather than quietly accepting real records.
 */
export interface IngestionStatus {
  enabled: boolean;
  production_like: boolean;
  dataset_mode: string;
  require_synthetic: boolean;
  max_batch_size: number;
  hard_max_batch_size: number;
  max_errors_returned: number;
  hard_max_errors_returned: number;
  default_allow_partial: boolean;
  default_duplicate_strategy: string;
  /** How far ahead of now an `occurred_at` may be before it is rejected. */
  future_tolerance_minutes: number;
  caveats: string[];
}

export interface BatchRequest<T = Record<string, unknown>> {
  records: T[];
  options?: IngestionOptions;
}

/** The record shapes the server validates each batch against. */
export interface AccountIngestRecord {
  id?: string;
  account_type?: string;
  status?: string;
  created_at?: string;
  metadata_json?: Record<string, unknown> | null;
}

export interface TransactionIngestRecord {
  id?: string;
  reference: string;
  sender_account_id: string;
  receiver_account_id: string;
  amount: number;
  currency?: string;
  occurred_at: string;
  status?: string;
  channel?: string;
  metadata_json?: Record<string, unknown> | null;
}

export interface ComplaintIngestRecord {
  id?: string;
  reference: string;
  reported_at: string;
  category?: string;
  /** Required. The narrative is what tiers 4-5 correlation reads. */
  narrative_raw: string;
  transaction_reference?: string;
  victim_account_id?: string;
  suspected_account_id?: string;
  amount?: number;
  currency?: string;
  source?: string;
  metadata_json?: Record<string, unknown> | null;
}

export interface EntityIngestRecord {
  id?: string;
  entity_type: string;
  /** Identifiers are stored hashed; the display form is optional. */
  identifier_hash: string;
  identifier_display?: string;
  source?: string;
  first_seen_at?: string;
  last_seen_at?: string;
  metadata_json?: Record<string, unknown> | null;
}

export interface EntityLinkIngestRecord {
  id?: string;
  account_id: string;
  entity_id: string;
  match_method?: string;
  /** 0 to 1. Omit for a deterministic match rather than sending 1. */
  confidence?: number;
  verification_state?: string;
  valid_from?: string;
  valid_to?: string;
  source?: string;
  metadata_json?: Record<string, unknown> | null;
}
