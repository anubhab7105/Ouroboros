/** Shared axis and grid styling, so every chart looks like the same chart. */
export const AXIS_PROPS = {
  stroke: 'currentColor',
  tick: { fontSize: 10, fill: 'currentColor' },
  tickLine: false,
  axisLine: false,
} as const;

export const GRID_PROPS = {
  stroke: 'currentColor',
  strokeOpacity: 0.12,
  strokeDasharray: '2 4',
  vertical: false,
} as const;

/**
 * Tooltip styling.
 *
 * Recharts renders tooltips with inline styles, so these cannot be Tailwind
 * classes; the values match the `--mg-surface` tokens closely enough that the
 * tooltip does not look foreign in either theme.
 */
export const TOOLTIP_PROPS = {
  contentStyle: {
    fontSize: 11,
    borderRadius: 6,
    border: '1px solid rgb(148 163 184 / 0.4)',
    background: 'rgb(255 255 255 / 0.98)',
    color: '#111620',
    padding: '6px 8px',
    boxShadow: '0 4px 12px rgb(15 23 42 / 0.12)',
  },
  labelStyle: { fontWeight: 600, marginBottom: 2 },
  itemStyle: { padding: 0 },
} as const;
