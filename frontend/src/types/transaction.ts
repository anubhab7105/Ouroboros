import type { Iso8601, PageResponse } from './common';

/** Transaction types, mirroring `app/api/v1/endpoints/transactions.py`. */

export type TransactionStatus = 'PENDING' | 'COMPLETED' | 'FAILED' | 'REVERSED';
export type Channel = 'UPI' | 'IMPS' | 'NEFT' | 'RTGS' | 'CARD' | 'INTERNAL';

/** `both` is the server's default when `account_id` is supplied. */
export type TransactionDirection = 'inbound' | 'outbound' | 'both';

/**
 * A transaction as the global ledger returns it.
 *
 * There is no `is_fund_movement` flag and no direction: both are derived.
 * Only `status === 'COMPLETED'` counts as fund movement — every aggregate in
 * the platform applies that rule — and direction only means something
 * relative to a particular account, which the global list does not have.
 */
export interface Transaction {
  id: string;
  sender_account_id: string;
  receiver_account_id: string;
  amount: number;
  currency: string;
  occurred_at: Iso8601;
  status: string;
  channel: string;
  reference: string;
  metadata_json?: Record<string, unknown> | null;
  record_created_at?: Iso8601 | null;
  record_updated_at?: Iso8601 | null;
}

/**
 * A transaction as the per-account endpoint returns it.
 *
 * This shape carries `direction` and `counterparty_account_id` because the
 * request named the account they are relative to; it does *not* carry the
 * sender and receiver ids.
 */
export interface AccountTransaction {
  id: string;
  direction: string;
  counterparty_account_id?: string | null;
  amount: number;
  currency: string;
  occurred_at: Iso8601;
  status: string;
  channel: string;
  reference: string;
  metadata_json?: Record<string, unknown> | null;
  record_created_at?: Iso8601 | null;
}

/** Bounded account summary returned alongside a transaction. */
export interface TransactionAccountSummary {
  id: string;
  account_type: string;
  status: string;
  created_at: Iso8601;
  record_created_at?: Iso8601 | null;
  record_updated_at?: Iso8601 | null;
}

export interface TransactionDetail {
  transaction: Transaction;
  sender_account?: TransactionAccountSummary | null;
  receiver_account?: TransactionAccountSummary | null;
  caveats: string[];
}

export type TransactionListResponse = PageResponse<Transaction>;
export type AccountTransactionListResponse = PageResponse<AccountTransaction>;

/** True only for a completed transfer. The one rule every total obeys. */
export function isFundMovement(transaction: { status: string }): boolean {
  return transaction.status === 'COMPLETED';
}

/** Direction of a ledger row relative to one account, or null if unrelated. */
export function directionFor(
  transaction: Transaction,
  accountId: string | null | undefined,
): 'inbound' | 'outbound' | null {
  if (!accountId) return null;
  if (transaction.sender_account_id === accountId) return 'outbound';
  if (transaction.receiver_account_id === accountId) return 'inbound';
  return null;
}

export interface TransactionFilters {
  sender_account_id?: string;
  receiver_account_id?: string;
  /** When set, `direction` and `counterparty_account_id` are relative to it. */
  account_id?: string;
  direction?: TransactionDirection;
  counterparty_account_id?: string;
  status?: string;
  channel?: string;
  currency?: string;
  reference?: string;
  /** The ledger's date bounds use these names, not `occurred_*`. */
  date_from?: string;
  date_to?: string;
  min_amount?: number;
  max_amount?: number;
  include_accounts?: boolean;
  q?: string;
}
