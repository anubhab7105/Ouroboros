import { Bar, BarChart, CartesianGrid, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

import { formatCount } from '@/lib/amounts';
import { CHART_SERIES_COLORS } from '@/lib/constants';
import type { FriendlyError } from '@/lib/errorMapper';
import { humaniseEnum, truncateText } from '@/lib/formatters';
import type { CategoryCount } from '@/types/dashboard';

import { ChartFrame } from './ChartFrame';
import { AXIS_PROPS, GRID_PROPS, TOOLTIP_PROPS } from './chartProps';

export interface ComplaintsByCategoryChartProps {
  data: CategoryCount[];
  isLoading?: boolean;
  error?: FriendlyError | null;
  onRetry?: () => void;
  /** Categories beyond this are collected into "Other". */
  maxCategories?: number;
  onSelectCategory?: (category: string) => void;
  height?: number;
}

/**
 * Complaint volume per category.
 *
 * A long tail is folded into a single "Other" bar rather than dropped, and the
 * tooltip names how many categories it stands for. Dropping the tail would
 * make the bars look like the whole picture when they are not, and plotting
 * forty categories makes none of them readable.
 */
export function ComplaintsByCategoryChart({
  data,
  isLoading = false,
  error = null,
  onRetry,
  maxCategories = 8,
  onSelectCategory,
  height = 240,
}: ComplaintsByCategoryChartProps) {
  const sorted = [...data].sort((a, b) => b.count - a.count);
  const head = sorted.slice(0, maxCategories);
  const tail = sorted.slice(maxCategories);

  const rows = [
    ...head.map((row) => ({
      key: row.category,
      label: truncateText(humaniseEnum(row.category), 28),
      count: row.count,
      collapsed: 0,
    })),
    ...(tail.length > 0
      ? [
          {
            key: '__other__',
            label: `Other (${tail.length})`,
            count: tail.reduce((sum, row) => sum + row.count, 0),
            collapsed: tail.length,
          },
        ]
      : []),
  ];

  const total = sorted.reduce((sum, row) => sum + row.count, 0);

  const summary =
    rows.length === 0
      ? 'Complaints by category: no complaints in this window.'
      : `Complaints by category, ${formatCount(total)} in total: ` +
        rows.map((row) => `${row.label} ${formatCount(row.count)}`).join(', ') +
        '.';

  return (
    <ChartFrame
      height={height}
      isLoading={isLoading}
      error={error}
      onRetry={onRetry}
      isEmpty={rows.length === 0}
      emptyTitle="No complaints in this window"
      summary={summary}
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={rows} layout="vertical" margin={{ top: 2, right: 44, bottom: 2, left: 4 }}>
          <CartesianGrid {...GRID_PROPS} vertical horizontal={false} />

          <XAxis type="number" {...AXIS_PROPS} allowDecimals={false} hide />
          <YAxis
            type="category"
            dataKey="label"
            {...AXIS_PROPS}
            width={150}
            tick={{ fontSize: 10, fill: 'currentColor' }}
          />

          <Tooltip
            {...TOOLTIP_PROPS}
            formatter={(value: number, _name, entry) => {
              const collapsed = (entry?.payload as { collapsed?: number } | undefined)?.collapsed;
              return [
                collapsed
                  ? `${formatCount(value)} complaints across ${collapsed} further categories`
                  : `${formatCount(value)} complaints`,
                'Complaints',
              ];
            }}
          />

          <Bar
            dataKey="count"
            name="Complaints"
            fill={CHART_SERIES_COLORS[5]}
            radius={[0, 3, 3, 0]}
            cursor={onSelectCategory ? 'pointer' : undefined}
            onClick={
              onSelectCategory
                ? (entry: unknown) => {
                    const key = (entry as { payload?: { key?: string } })?.payload?.key;
                    if (key && key !== '__other__') onSelectCategory(key);
                  }
                : undefined
            }
          >
            <LabelList
              dataKey="count"
              position="right"
              formatter={(value: number) => formatCount(value)}
              style={{ fontSize: 10, fill: 'currentColor', fontVariantNumeric: 'tabular-nums' }}
            />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartFrame>
  );
}
