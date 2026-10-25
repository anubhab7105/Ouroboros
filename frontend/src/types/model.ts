import type { Iso8601, PageResponse } from './common';

/**
 * Model monitoring and report types, mirroring
 * `app/api/v1/endpoints/model_metrics.py` and `.../reports.py`.
 *
 * The shape of this module is driven by one fact: a deployment may have no
 * trained model at all. Scores are still produced — by the heuristic fallback
 * — and every response here is built to make which of the two is in force
 * unmistakable, because the claims a report may make depend on it.
 */

export interface ModelVersion {
  id: string;
  version: string;
  feature_schema_version: string;
  model_type: string;
  training_seed?: number | null;
  training_started_at?: Iso8601 | null;
  training_finished_at?: Iso8601 | null;
  /** Identifies the exact dataset trained on, for reproducibility. */
  dataset_fingerprint?: string | null;
  generator_config_json?: Record<string, unknown> | null;
  split_strategy: string;
  hyperparameters_json?: Record<string, unknown> | null;
  artifact_checksum?: string | null;
  checksum_algorithm?: string | null;
  /** False when the row exists but the artefact file is missing on disk. */
  artifact_available: boolean;
  metrics_json?: Record<string, unknown> | null;
  limitations_json?: Record<string, unknown> | null;
  is_active: boolean;
  notes?: string | null;
  created_at?: Iso8601 | null;
  updated_at?: Iso8601 | null;
}

export type ModelVersionListResponse = PageResponse<ModelVersion>;

export interface ModelEvaluation {
  id: string;
  model_version_id: string;
  dataset_fingerprint?: string | null;
  /** How the holdout was cut. A temporal split is the only honest one here. */
  split_strategy: string;
  sample_count: number;
  class_distribution_json?: Record<string, unknown> | null;
  /** Open map: metric name to value. Metric sets change between versions. */
  metrics_summary: Record<string, unknown>;
  limitations?: string | null;
  created_at?: Iso8601 | null;
  updated_at?: Iso8601 | null;
}

export type ModelEvaluationListResponse = PageResponse<ModelEvaluation>;

export interface ModelMetricsStatus {
  enabled: boolean;
  scoring_mode: string;
  active_model_version?: string | null;
  /** What to call the scorer when no trained model is active. */
  fallback_label: string;
  require_trained_model: boolean;
  dataset_mode: string;
  feature_schema_version: string;
  artifact_status: Record<string, unknown>;
  feature_schema_available: boolean;
  caveats: string[];
}

export interface ModelCurrent {
  scoring_mode: string;
  active_model_version?: string | null;
  fallback_label: string;
  require_trained_model: boolean;
  feature_schema_version: string;
  active_version?: ModelVersion | null;
  latest_evaluations: ModelEvaluation[];
  caveats: string[];
}

/**
 * What may and may not be claimed about the current scorer.
 *
 * These are machine-readable guard rails, not decoration.
 * `probability_claim_allowed` false means the score must never be described as
 * a likelihood of fraud; `calibration_claim_allowed` false means it must not
 * be described as calibrated. The UI renders scores accordingly rather than
 * leaving it to whoever writes the copy.
 */
export interface ModelLimitations {
  scoring_mode: string;
  calibration_claim_allowed: boolean;
  probability_claim_allowed: boolean;
  synthetic_only: boolean;
  production_ready: boolean;
  limitations_summary: string;
  caveats: string[];
}

/**
 * The feature schema in force.
 *
 * `forbidden_fields` is the list of inputs the schema explicitly refuses —
 * protected attributes and proxies for them. It is shown in the interface so
 * that the exclusion is auditable rather than a claim in a document.
 */
export interface FeatureSchema {
  available: boolean;
  feature_schema_version: string;
  feature_fields: string[];
  feature_windows: string[];
  forbidden_fields: string[];
  fallback_label: string;
  schema?: Record<string, unknown> | null;
  caveats: string[];
}

export interface ModelComparison {
  versions: ModelVersion[];
  latest_evaluations: ModelEvaluation[];
  /** The union of metric names across the compared versions. */
  metric_keys: string[];
  caveats: string[];
}

// ---------------------------------------------------------------- reports

/** One labelled line in a report preview or evidence index. */
export interface ReportRow {
  label: string;
  value: string;
  evidence_refs: string[];
}

export interface ReportSectionSummary {
  key: string;
  title: string;
  item_count: number;
  /** True when the section hit the per-section item cap. */
  truncated: boolean;
  note?: string | null;
  evidence_refs: string[];
}

/**
 * A report preview.
 *
 * Previewing is itself an audited action in most configurations, because the
 * preview contains the same material as the PDF.
 */
export interface ReportPreview {
  case_id: string;
  case_title: string;
  generated_at: Iso8601;
  generated_by: string;
  timezone_label: string;
  sections: ReportRow[];
  section_summaries: ReportSectionSummary[];
  evidence_index: ReportRow[];
  evidence_total: number;
  evidence_truncated: boolean;
  estimated_pages: number;
  page_limit: number;
  item_limit: number;
  generation_seconds: number;
  disclaimer: string;
  limitations: string;
  footer: string;
  caveats: string[];
}

export interface ReportEvidenceIndex {
  case_id: string;
  items: ReportRow[];
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
  sort_by?: string | null;
  sort_order: string;
  caveats: string[];
}

/**
 * The result of generating a report.
 *
 * `sha256` is the digest of the produced PDF. It is shown so that a report
 * handed on to someone else can be shown to be the same file that was
 * generated here.
 */
export interface ReportGenerateResult {
  case_id: string;
  case_title: string;
  filename: string;
  content_type: string;
  size_bytes: number;
  sha256: string;
  generated_at: Iso8601;
  generated_by: string;
  sections: ReportSectionSummary[];
  evidence_total: number;
  evidence_truncated: boolean;
  estimated_pages: number;
  page_limit: number;
  item_limit: number;
  generation_seconds: number;
  renderer: string;
  caveats: string[];
}

export interface ReportLimitations {
  disclaimer: string;
  limitations: string;
  footer: string;
  caveats: string[];
}

/**
 * Report generation settings.
 *
 * `renderer_available` false means ReportLab is not installed, so previews
 * work and downloads do not. Saying so before the button is pressed is better
 * than a 503 after a case has been written up.
 */
export interface ReportStatus {
  enabled: boolean;
  renderer_available: boolean;
  renderer: string;
  max_items_per_section: number;
  max_pages: number;
  max_generation_seconds: number;
  filename_prefix: string;
  timezone_label: string;
  include_disclaimer: boolean;
  include_limitations: boolean;
  include_evidence_index: boolean;
  audit_generation: boolean;
  audit_preview: boolean;
  caveats: string[];
}
