import { endpoints } from '@/lib/api';
import { get, post } from '@/lib/apiClient';
import type {
  AccountIngestRecord,
  BatchIngestResult,
  BatchRequest,
  ComplaintIngestRecord,
  EntityIngestRecord,
  EntityLinkIngestRecord,
  IngestEntityType,
  IngestionOptions,
  IngestionStatus,
  TransactionIngestRecord,
} from '@/types/ingestion';

/**
 * Ingestion.
 *
 * All five endpoints take `{ records, options }` and return the same batch
 * result. `dry_run` is worth using first on anything hand-assembled: it
 * validates every row and reports the errors without writing, which turns a
 * half-loaded dataset into a list of corrections.
 */

export async function fetchIngestionStatus(): Promise<IngestionStatus> {
  return get<IngestionStatus>(endpoints.ingestion.status());
}

const ENDPOINTS: Record<IngestEntityType, () => string> = {
  accounts: endpoints.ingestion.accounts,
  transactions: endpoints.ingestion.transactions,
  complaints: endpoints.ingestion.complaints,
  entities: endpoints.ingestion.entities,
  'entity-links': endpoints.ingestion.entityLinks,
};

export async function ingestBatch(
  entityType: IngestEntityType,
  records: object[],
  options?: IngestionOptions,
): Promise<BatchIngestResult> {
  const body: BatchRequest<object> = { records, options };
  return post<BatchIngestResult>(ENDPOINTS[entityType](), body);
}

export async function ingestAccounts(
  records: AccountIngestRecord[],
  options?: IngestionOptions,
): Promise<BatchIngestResult> {
  return ingestBatch('accounts', records, options);
}

export async function ingestTransactions(
  records: TransactionIngestRecord[],
  options?: IngestionOptions,
): Promise<BatchIngestResult> {
  return ingestBatch('transactions', records, options);
}

export async function ingestComplaints(
  records: ComplaintIngestRecord[],
  options?: IngestionOptions,
): Promise<BatchIngestResult> {
  return ingestBatch('complaints', records, options);
}

export async function ingestEntities(
  records: EntityIngestRecord[],
  options?: IngestionOptions,
): Promise<BatchIngestResult> {
  return ingestBatch('entities', records, options);
}

export async function ingestEntityLinks(
  records: EntityLinkIngestRecord[],
  options?: IngestionOptions,
): Promise<BatchIngestResult> {
  return ingestBatch('entity-links', records, options);
}

/** The order batches must be loaded in, because of foreign keys. */
export const INGEST_ORDER: IngestEntityType[] = [
  'accounts',
  'transactions',
  'complaints',
  'entities',
  'entity-links',
];
