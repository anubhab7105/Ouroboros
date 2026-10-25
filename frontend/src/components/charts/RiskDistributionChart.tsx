import { Bar, BarChart, CartesianGrid, Cell, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

import { formatCount, formatPercent } from '@/lib/amounts';
import { RISK_BAND_TOKENS } from '@/lib/constants';
import type { FriendlyError } from '@/lib/errorMapper';
import { humaniseEnum } from '@/lib/formatters';
import type { RiskBand } from '@/types/common';

import { ChartFrame } from './ChartFrame';
import { AXIS_PROPS, GRID_PROPS, TOOLTIP_PROPS } from './chartProps';

export interface RiskDistributionChartProps {
  /**
   * Band counts as the server returns them: an open map, because a band added
   * on the backend must still show up here. Unknown keys are collected into a
   * final row rather than dropped.
   */
  counts?: Record<string, number>;
  isLoading?: boolean;
  error?: FriendlyError | null;
  onRetry?: () => void;
  onSelectBand?: (band: RiskBand) => void;
  height?: number;
}

const ORDER: RiskBand[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

/**
 * How assessed accounts are spread across the risk bands.
 *
 * A horizontal bar chart rather than a pie: there are four categories with
 * wildly different magnitudes (LOW usually dominates by two orders of
 * magnitude), and comparing lengths against a shared axis works at that
 * ratio where comparing angles does not.
 *
 * The count of *assessed* accounts is what this divides up. Accounts that
 * were never scored are not a band and are not folded into LOW.
 */
export function RiskDistributionChart({
  counts,
  isLoading = false,
  error = null,
  onRetry,
  onSelectBand,
  height = 200,
}: RiskDistributionChartProps) {
  const source = counts ?? {};
  const total = Object.values(source).reduce((sum, value) => sum + (value ?? 0), 0);

  // Any band the backend reports that this build does not know about is kept
  // and shown last, rather than silently excluded from a distribution that
  // then does not add up to its own total.
  const unknownKeys = Object.keys(source).filter(
    (key) => !(ORDER as readonly string[]).includes(key),
  );

  const rows = [
    ...ORDER.map((band) => ({
      band: band as string,
      label: RISK_BAND_TOKENS[band].label,
      hex: RISK_BAND_TOKENS[band].hex,
      count: source[band] ?? 0,
      share: total > 0 ? (source[band] ?? 0) / total : 0,
    })),
    ...unknownKeys.map((key) => ({
      band: key,
      label: humaniseEnum(key),
      hex: '#6b7a8f',
      count: source[key] ?? 0,
      share: total > 0 ? (source[key] ?? 0) / total : 0,
    })),
  ];

  const summary =
    total === 0
      ? 'Risk distribution chart: no accounts assessed in this window.'
      : `Risk distribution across ${formatCount(total)} assessed accounts: ` +
        rows
          .map((row) => `${row.label} ${formatCount(row.count)} (${formatPercent(row.share)})`)
          .join(', ') +
        '.';

  return (
    <ChartFrame
      height={height}
      isLoading={isLoading}
      error={error}
      onRetry={onRetry}
      isEmpty={total === 0}
      emptyTitle="No accounts assessed in this window"
      emptyMessage="Risk bands appear once an analysis run has produced assessments."
      summary={summary}
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={rows}
          layout="vertical"
          margin={{ top: 2, right: 48, bottom: 2, left: 4 }}
          barCategoryGap="22%"
        >
          <CartesianGrid {...GRID_PROPS} vertical horizontal={false} />

          <XAxis type="number" {...AXIS_PROPS} allowDecimals={false} hide />
          <YAxis
            type="category"
            dataKey="label"
            {...AXIS_PROPS}
            width={64}
            tick={{ fontSize: 11, fill: 'currentColor' }}
          />

          <Tooltip
            {...TOOLTIP_PROPS}
            formatter={(value: number, _name, entry) => [
              `${formatCount(value)} accounts (${formatPercent(
                (entry?.payload as { share?: number } | undefined)?.share ?? 0,
              )})`,
              'Accounts',
            ]}
          />

          <Bar
            dataKey="count"
            name="Accounts"
            radius={[0, 3, 3, 0]}
            onClick={
              onSelectBand
                ? (entry: unknown) => {
                    const band = (entry as { payload?: { band?: string } })?.payload?.band;
                    if (band && (ORDER as readonly string[]).includes(band)) {
                      onSelectBand(band as RiskBand);
                    }
                  }
                : undefined
            }
            cursor={onSelectBand ? 'pointer' : undefined}
          >
            {rows.map((row) => (
              <Cell key={row.band} fill={row.hex} />
            ))}

            {/* The number is printed on every bar: at these ratios the LOW bar
                is the only one with a readable length. */}
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
