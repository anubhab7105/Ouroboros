import { cleanParams, endpoints, pageParams } from '@/lib/api';
import { get } from '@/lib/apiClient';
import type { AlertListResponse } from '@/types/alert';
import type { PageQuery } from '@/types/common';
import type { ComplaintCorrelationListResponse } from '@/types/complaint';
import type {
  AccountTransactionListResponse,
  TransactionDetail,
  TransactionFilters,
  TransactionListResponse,
} from '@/types/transaction';

/**
 * Transaction reads.
 *
 * Note the two list shapes. `/transactions` returns rows with sender and
 * receiver ids; `/accounts/{id}/transactions` returns rows with a direction
 * and a counterparty, because the request named the account they are relative
 * to. They are different types on purpose and are not interchangeable.
 */

export async function fetchTransactions(
  page: PageQuery & { filters: TransactionFilters },
): Promise<TransactionListResponse> {
  const { filters, ...rest } = page;

  return get<TransactionListResponse>(endpoints.transactions.list(), {
    params: { ...pageParams(rest), ...cleanParams(filters) },
  });
}

export async function fetchAccountTransactions(
  accountId: string,
  page: PageQuery & { filters?: TransactionFilters },
): Promise<AccountTransactionListResponse> {
  const { filters = {}, ...rest } = page;

  return get<AccountTransactionListResponse>(endpoints.accounts.transactions(accountId), {
    params: { ...pageParams(rest), ...cleanParams(filters) },
  });
}

export async function fetchTransaction(
  id: string,
  includeAccounts = true,
): Promise<TransactionDetail> {
  return get<TransactionDetail>(endpoints.transactions.detail(id), {
    params: { include_accounts: includeAccounts },
  });
}

export async function fetchTransactionCorrelations(
  id: string,
  page: PageQuery = {},
): Promise<ComplaintCorrelationListResponse> {
  return get<ComplaintCorrelationListResponse>(endpoints.transactions.complaintCorrelations(id), {
    params: pageParams(page),
  });
}

export async function fetchTransactionAlerts(
  id: string,
  page: PageQuery = {},
): Promise<AlertListResponse> {
  return get<AlertListResponse>(endpoints.transactions.alerts(id), {
    params: pageParams(page),
  });
}

/**
 * The evidence bundle for one transaction.
 *
 * Same shape as the detail response. It exists as its own endpoint so that
 * attaching a transaction to a case captures one atomic snapshot rather than
 * stitching several reads together.
 */
export async function fetchTransactionEvidence(id: string): Promise<TransactionDetail> {
  return get<TransactionDetail>(endpoints.transactions.evidence(id));
}
