import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { formatCount } from '@/lib/amounts';
import { CHART_SERIES_COLORS } from '@/lib/constants';
import { formatBucketLabel } from '@/lib/dates';
import type { FriendlyError } from '@/lib/errorMapper';
import type { DashboardTrends } from '@/types/dashboard';

import { ChartFrame } from './ChartFrame';
import { AXIS_PROPS, GRID_PROPS, TOOLTIP_PROPS } from './chartProps';

export interface AlertsTrendChartProps {
  data?: DashboardTrends;
  isLoading?: boolean;
  error?: FriendlyError | null;
  onRetry?: () => void;
  /** Which series to draw. Fewer lines read better; three is the useful set. */
  series?: Array<'alerts' | 'cases' | 'complaints' | 'transactions' | 'assessments'>;
  height?: number;
}

const SERIES_META = {
  alerts: {
    label: 'Alerts raised',
    colour: CHART_SERIES_COLORS[1],
    help: 'Alerts first seen in the bucket. Re-fired signatures update an existing alert and are not counted again.',
  },
  cases: {
    label: 'Cases opened',
    colour: CHART_SERIES_COLORS[0],
    help: 'Cases created in the bucket.',
  },
  complaints: {
    label: 'Complaints',
    colour: CHART_SERIES_COLORS[4],
    help: 'Complaints reported in the bucket, by report date rather than ingestion date.',
  },
  transactions: {
    label: 'Transactions',
    colour: CHART_SERIES_COLORS[2],
    help: 'All transactions in the bucket, including those that are not fund movement.',
  },
  assessments: {
    label: 'Assessments',
    colour: CHART_SERIES_COLORS[5],
    help: 'Assessments persisted in the bucket. A flat line here means no analysis ran.',
  },
} as const;

/**
 * Daily activity over the window.
 *
 * Lines rather than stacked areas, because these series answer different
 * questions and do not sum to anything meaningful: stacking "complaints" on
 * top of "alerts" would invent a total that means nothing.
 *
 * The *assessments* series is the one that explains the others. A fortnight of
 * zero alerts looks like a quiet fortnight until you notice assessments were
 * also zero, which means nothing was analysed. That distinction is the
 * difference between "no fraud found" and "we did not look", so the series is
 * offered by default.
 *
 * Bucket labels follow the server's `bucket_size` rather than assuming days.
 */
export function AlertsTrendChart({
  data,
  isLoading = false,
  error = null,
  onRetry,
  series = ['alerts', 'cases', 'assessments'],
  height = 260,
}: AlertsTrendChartProps) {
  const points = data?.points ?? [];
  const bucketSize = (data?.bucket_size ?? 'day') as 'hour' | 'day' | 'week' | 'month';

  const totals = series.map((key) => ({
    key,
    label: SERIES_META[key].label,
    total: points.reduce((sum, point) => sum + (point[key] ?? 0), 0),
  }));

  const summary =
    points.length === 0
      ? 'Activity trend chart: no activity in this window.'
      : `Activity trend over ${points.length} ${bucketSize} buckets, ` +
        `${points[0]!.date} to ${points[points.length - 1]!.date}: ` +
        totals.map((entry) => `${entry.label} ${formatCount(entry.total)}`).join(', ') +
        '.';

  return (
    <div>
      <ChartFrame
        height={height}
        isLoading={isLoading}
        error={error}
        onRetry={onRetry}
        isEmpty={points.length === 0}
        emptyTitle="No activity in this window"
        emptyMessage="Widen the date range, or load data and start an analysis run from the Data page."
        summary={summary}
      >
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={points} margin={{ top: 4, right: 8, bottom: 0, left: -12 }}>
            <CartesianGrid {...GRID_PROPS} />

            <XAxis
              dataKey="date"
              {...AXIS_PROPS}
              tickFormatter={(value: string) => formatBucketLabel(value, bucketSize)}
              minTickGap={24}
            />
            <YAxis {...AXIS_PROPS} allowDecimals={false} width={44} />

            <Tooltip
              {...TOOLTIP_PROPS}
              labelFormatter={(value: string) => formatBucketLabel(value, bucketSize)}
              formatter={(value: number, name: string) => [formatCount(value), name]}
            />
            <Legend wrapperStyle={{ fontSize: 10, paddingTop: 4 }} />

            {series.map((key) => (
              <Line
                key={key}
                type="monotone"
                dataKey={key}
                name={SERIES_META[key].label}
                stroke={SERIES_META[key].colour}
                strokeWidth={1.75}
                dot={false}
                activeDot={{ r: 3 }}
              />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </ChartFrame>

      <ul className="mt-1.5 space-y-0.5">
        {series.map((key) => (
          <li key={key} className="text-2xs text-ink-500 dark:text-ink-400">
            <span className="font-medium text-ink-700 dark:text-ink-200">
              {SERIES_META[key].label}:
            </span>{' '}
            {SERIES_META[key].help}
          </li>
        ))}
      </ul>
    </div>
  );
}
