import { Fragment } from 'react';
import { Link } from 'react-router-dom';

import { Badge } from '@/components/common/Badge';
import { Button } from '@/components/common/Button';
import { DataTable, type Column } from '@/components/common/DataTable';
import { formatAmount } from '@/lib/amounts';
import { formatDate } from '@/lib/dates';
import { truncateId } from '@/lib/formatters';
import { paths } from '@/routes/paths';
import { accountChain, singleCurrencyTotal, type GraphPath, type MoneyTrail } from '@/types/graph';

/** Either shape works: both carry a chain of nodes and per-currency totals. */
export type PathLike = GraphPath | MoneyTrail;

export interface PathResultsTableProps {
  rows: PathLike[];
  isLoading?: boolean;
  /** Show this path on the graph canvas. */
  onHighlight?: (item: PathLike) => void;
  /** Attach it to a case as GRAPH_PATH evidence. */
  onAttach?: (item: PathLike) => void;
  emptyMessage?: string;
}

function rowKey(item: PathLike): string {
  return 'path_id' in item ? item.path_id : item.trail_id;
}

/**
 * Paths and money trails between accounts.
 *
 * The important restraint here is what the table does *not* compute. There is
 * no "throughput ratio" and no single total, because:
 *
 * - **Totals are per currency.** The API returns `amount_by_currency`, and
 *   summing across currencies would invent an exchange rate the platform does
 *   not hold. A single-currency path shows its total; a mixed one lists each.
 *
 * - **A path is a shape, not a tracing.** Money is fungible, and these are
 *   transfer records between accounts. That a chain of transfers exists is an
 *   investigative lead; that the same funds traversed it is a claim the data
 *   cannot support, and the column header and tooltip both say so.
 *
 * What the table does show is hop count, the accounts in order, the time span,
 * and the amounts — the facts an investigator can check against the ledger.
 */
export function PathResultsTable({
  rows,
  isLoading,
  onHighlight,
  onAttach,
  emptyMessage,
}: PathResultsTableProps) {
  const columns: Array<Column<PathLike>> = [
    {
      key: 'hop_count',
      header: 'Hops',
      numeric: true,
      render: (row) => <span className="text-xs tabular font-medium">{row.hop_count}</span>,
      width: '7%',
    },
    {
      key: 'chain',
      header: 'Accounts in order',
      render: (row) => {
        const chain = accountChain(row);

        return (
          <span className="flex flex-wrap items-center gap-1">
            {chain.map((accountId, index) => (
              <Fragment key={`${accountId}-${index}`}>
                {index > 0 ? (
                  <span aria-hidden="true" className="text-ink-400 dark:text-ink-500">
                    →
                  </span>
                ) : null}
                <Link
                  to={paths.account(accountId)}
                  title={accountId}
                  className="font-mono text-2xs text-accent-700 hover:underline dark:text-accent-300"
                >
                  {truncateId(accountId, 5)}
                </Link>
              </Fragment>
            ))}
            <span className="mg-visually-hidden">
              {chain.length} accounts, in traversal order
            </span>
          </span>
        );
      },
      width: '38%',
    },
    {
      key: 'amount',
      header: 'Transferred',
      numeric: true,
      render: (row) => {
        const single = singleCurrencyTotal(row.amount_by_currency);

        if (single) {
          return (
            <span
              className="whitespace-nowrap text-xs tabular"
              title="Total of the transfers along this chain, in the one currency they share. It is not a claim that this sum moved end to end."
            >
              {formatAmount(single.amount, single.currency)}
            </span>
          );
        }

        const entries = Object.entries(row.amount_by_currency ?? {});

        if (entries.length === 0) {
          return <span className="text-2xs text-ink-400 dark:text-ink-500">—</span>;
        }

        return (
          <span
            className="flex flex-col items-end"
            title="This chain spans more than one currency. The figures are kept apart because there is no rate to combine them with."
          >
            {entries.map(([currency, amount]) => (
              <span key={currency} className="whitespace-nowrap text-2xs tabular">
                {formatAmount(amount, currency)}
              </span>
            ))}
          </span>
        );
      },
      width: '17%',
    },
    {
      key: 'span',
      header: 'Time span',
      render: (row) => (
        <span className="whitespace-nowrap text-2xs text-ink-600 dark:text-ink-300">
          {row.earliest_at || row.latest_at ? (
            <>
              {formatDate(row.earliest_at)}
              {row.latest_at && row.latest_at !== row.earliest_at ? (
                <> → {formatDate(row.latest_at)}</>
              ) : null}
            </>
          ) : (
            '—'
          )}
        </span>
      ),
      hideOnSmall: true,
      width: '16%',
    },
    {
      key: 'direction',
      header: 'Direction',
      render: (row) => (
        <Badge
          tone="neutral"
          title={
            row.direction === 'incoming'
              ? 'Traversed towards the root account.'
              : 'Traversed away from the root account.'
          }
        >
          {row.direction === 'incoming' ? 'Inbound' : 'Outbound'}
        </Badge>
      ),
      hideOnSmall: true,
      width: '10%',
    },
    ...(onHighlight || onAttach
      ? [
          {
            key: 'actions',
            header: <span className="mg-visually-hidden">Actions</span>,
            render: (row: PathLike) => (
              <span className="flex items-center gap-1">
                {onHighlight ? (
                  <Button size="sm" variant="ghost" onClick={() => onHighlight(row)}>
                    Show
                  </Button>
                ) : null}
                {onAttach ? (
                  <Button size="sm" variant="ghost" onClick={() => onAttach(row)}>
                    Attach
                  </Button>
                ) : null}
              </span>
            ),
            width: '12%',
          } satisfies Column<PathLike>,
        ]
      : []),
  ];

  return (
    <DataTable
      caption="Transfer chains between the chosen accounts, with per-currency totals"
      columns={columns}
      rows={rows}
      rowKey={rowKey}
      isLoading={isLoading}
      emptyTitle="No chain found"
      emptyMessage={
        emptyMessage ??
        'No chain within the hop limit and time window. That is not evidence no connection exists — raise the hop limit, widen the window, or check whether the traversal was truncated.'
      }
    />
  );
}
