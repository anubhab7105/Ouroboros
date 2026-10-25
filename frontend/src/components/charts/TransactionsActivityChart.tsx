import {
  Bar,
  CartesianGrid,
  ComposedChart,
  Legend,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { formatCompactAmount, formatCount } from '@/lib/amounts';
import { CHART_SERIES_COLORS } from '@/lib/constants';
import { formatBucketLabel } from '@/lib/dates';
import type { FriendlyError } from '@/lib/errorMapper';

import { ChartFrame } from './ChartFrame';
import { AXIS_PROPS, GRID_PROPS, TOOLTIP_PROPS } from './chartProps';

export interface ActivityBucket {
  bucket: string;
  count: number;
  /** Total completed value in the bucket. Null when value is unavailable. */
  value?: number | null;
}

export interface TransactionsActivityChartProps {
  buckets: ActivityBucket[];
  granularity?: 'hour' | 'day' | 'week' | 'month';
  currency?: string;
  isLoading?: boolean;
  error?: FriendlyError | null;
  onRetry?: () => void;
  height?: number;
}

/**
 * Transaction count and value over time.
 *
 * Two axes, which is usually a thing to avoid — but count and value are the
 * pair that matters here: a hundred small transfers and one large one are
 * different stories, and the layering typologies this platform looks for show
 * up precisely as a divergence between the two lines. The axes are labelled
 * with their units so the reader is never guessing which belongs to which.
 *
 * Value is drawn as a line over counted bars, so the comparison is between
 * shapes rather than between two bar series competing for the same space.
 */
export function TransactionsActivityChart({
  buckets,
  granularity = 'day',
  currency,
  isLoading = false,
  error = null,
  onRetry,
  height = 240,
}: TransactionsActivityChartProps) {
  const hasValue = buckets.some((bucket) => typeof bucket.value === 'number');

  const totalCount = buckets.reduce((sum, bucket) => sum + bucket.count, 0);
  const totalValue = buckets.reduce((sum, bucket) => sum + (bucket.value ?? 0), 0);

  const summary =
    buckets.length === 0
      ? 'Transaction activity chart: no transactions in this window.'
      : `Transaction activity, ${granularity} buckets: ${formatCount(totalCount)} transactions` +
        (hasValue ? ` totalling ${formatCompactAmount(totalValue, currency)}` : '') +
        ` over ${buckets.length} buckets.`;

  return (
    <ChartFrame
      height={height}
      isLoading={isLoading}
      error={error}
      onRetry={onRetry}
      isEmpty={buckets.length === 0}
      emptyTitle="No transactions in this window"
      summary={summary}
    >
      <ResponsiveContainer width="100%" height="100%">
        <ComposedChart data={buckets} margin={{ top: 4, right: 4, bottom: 0, left: -12 }}>
          <CartesianGrid {...GRID_PROPS} />

          <XAxis
            dataKey="bucket"
            {...AXIS_PROPS}
            tickFormatter={(value: string) => formatBucketLabel(value, granularity)}
            minTickGap={24}
          />

          <YAxis
            yAxisId="count"
            {...AXIS_PROPS}
            allowDecimals={false}
            width={44}
            label={{
              value: 'Count',
              angle: -90,
              position: 'insideLeft',
              style: { fontSize: 9, fill: 'currentColor' },
            }}
          />

          {hasValue ? (
            <YAxis
              yAxisId="value"
              orientation="right"
              {...AXIS_PROPS}
              width={52}
              tickFormatter={(value: number) => formatCompactAmount(value)}
            />
          ) : null}

          <Tooltip
            {...TOOLTIP_PROPS}
            labelFormatter={(value: string) => formatBucketLabel(value, granularity)}
            formatter={(value: number, name: string) =>
              name === 'Value'
                ? [formatCompactAmount(value, currency), 'Value']
                : [formatCount(value), 'Transactions']
            }
          />
          <Legend wrapperStyle={{ fontSize: 10, paddingTop: 4 }} />

          <Bar
            yAxisId="count"
            dataKey="count"
            name="Transactions"
            fill={CHART_SERIES_COLORS[0]}
            radius={[2, 2, 0, 0]}
          />

          {hasValue ? (
            <Line
              yAxisId="value"
              type="monotone"
              dataKey="value"
              name="Value"
              stroke={CHART_SERIES_COLORS[1]}
              strokeWidth={1.75}
              dot={false}
              connectNulls={false}
            />
          ) : null}
        </ComposedChart>
      </ResponsiveContainer>
    </ChartFrame>
  );
}
