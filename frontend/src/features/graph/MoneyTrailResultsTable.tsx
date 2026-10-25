import { Badge } from '@/components/common/Badge';
import { Card } from '@/components/common/Card';
import { ErrorState } from '@/components/common/ErrorState';
import { PathResultsTable } from '@/components/tables/PathResultsTable';
import { formatCount } from '@/lib/amounts';
import type { FriendlyError } from '@/lib/errorMapper';
import { accountChain, type GraphPathsResult, type MoneyTrailsResult } from '@/types/graph';

export interface MoneyTrailResultsTableProps {
  trails?: MoneyTrailsResult;
  paths?: GraphPathsResult;
  isLoading?: boolean;
  error?: FriendlyError | null;
  onRetry?: () => void;
  /** Show the chain on the canvas. */
  onHighlight?: (accountIds: string[]) => void;
}

/**
 * Trail and path results.
 *
 * `truncated` gets its own sentence rather than a quiet badge. A truncated
 * search means the limit was reached before the search finished, so "no path
 * found" has not actually been established — and that is precisely the
 * sentence somebody is tempted to write into a case.
 */
export function MoneyTrailResultsTable({
  trails,
  paths,
  isLoading,
  error,
  onRetry,
  onHighlight,
}: MoneyTrailResultsTableProps) {
  const rows = paths ? paths.paths : (trails?.trails ?? []);
  const result = paths ?? trails;
  const truncated = result?.truncated ?? false;

  const title = paths ? 'Routes found' : 'Trails found';

  return (
    <Card
      title={title}
      description={
        paths
          ? `Chains of transfers connecting the two accounts, within ${paths.max_depth} hops.`
          : trails
            ? `Chains of transfers ${trails.direction === 'incoming' ? 'into' : 'out of'} the account, within ${trails.max_hops} hops.`
            : undefined
      }
      actions={
        result ? (
          <div className="flex items-center gap-1.5">
            <Badge tone="neutral">{formatCount(rows.length)} found</Badge>
            {truncated ? (
              <Badge
                tone="warning"
                title="The search stopped at a limit, so this is not necessarily every chain."
              >
                Truncated
              </Badge>
            ) : null}
          </div>
        ) : null
      }
      caveats={result?.caveats}
      flush
    >
      {error ? (
        <div className="p-4">
          <ErrorState error={error} onRetry={onRetry} compact />
        </div>
      ) : (
        <>
          {truncated ? (
            <p className="px-4 pt-3 text-2xs leading-relaxed text-ink-700 dark:text-ink-200">
              The search reached a limit before it finished. These are some of the chains, not
              necessarily all of them — so an absent route has not been ruled out, and a case
              should not state that no connection exists on the strength of this result.
            </p>
          ) : null}

          <PathResultsTable
            rows={rows}
            isLoading={isLoading}
            onHighlight={
              onHighlight ? (item) => onHighlight(accountChain(item)) : undefined
            }
            emptyMessage={
              result
                ? 'No chain within these limits. Raise the hop count, widen the dates, or lower the minimum transfer — and note that this is not evidence that no connection exists.'
                : 'Run a search to see results.'
            }
          />
        </>
      )}
    </Card>
  );
}
