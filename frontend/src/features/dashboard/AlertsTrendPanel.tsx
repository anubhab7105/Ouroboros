import { AlertsTrendChart } from '@/components/charts/AlertsTrendChart';
import { Card } from '@/components/common/Card';
import type { FriendlyError } from '@/lib/errorMapper';
import type { DashboardTrends } from '@/types/dashboard';

export interface AlertsTrendPanelProps {
  trends?: DashboardTrends;
  isLoading?: boolean;
  error?: FriendlyError | null;
  onRetry?: () => void;
}

/**
 * Activity over the window.
 *
 * The panel carries the server's caveats rather than restating them: the
 * trend endpoint explains its own bucketing and clamping, and the UI
 * paraphrasing that would be one more thing to keep in step.
 */
export function AlertsTrendPanel({ trends, isLoading, error, onRetry }: AlertsTrendPanelProps) {
  return (
    <Card
      title="Activity"
      description="Daily counts across the selected window. Operational signals, not forecasts."
      caveats={trends?.caveats}
    >
      <AlertsTrendChart
        data={trends}
        isLoading={isLoading}
        error={error}
        onRetry={onRetry}
        series={['alerts', 'cases', 'assessments']}
      />
    </Card>
  );
}
