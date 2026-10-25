import { useNavigate } from 'react-router-dom';

import { ComplaintsByCategoryChart } from '@/components/charts/ComplaintsByCategoryChart';
import { Card } from '@/components/common/Card';
import { KeyValueList } from '@/components/common/KeyValueList';
import { formatCount, formatPercent } from '@/lib/amounts';
import type { FriendlyError } from '@/lib/errorMapper';
import { paths } from '@/routes/paths';
import { toCategoryCounts, type DashboardComplaintBreakdown } from '@/types/dashboard';

export interface ComplaintSummaryPanelProps {
  complaints?: DashboardComplaintBreakdown;
  isLoading?: boolean;
  error?: FriendlyError | null;
  onRetry?: () => void;
}

/**
 * Complaints, and how far their correlations have been taken.
 *
 * The deterministic/inferred split is the thing to get across. A tier 1-2
 * correlation is an identity — the complaint names this transaction reference,
 * and it exists — and needs no confidence value. A tier 3-5 correlation is an
 * inference with a confidence attached, and until a human accepts it, it is a
 * lead rather than a finding. Collapsing the two into "correlations: 1,204"
 * would overstate what is known by a wide margin.
 */
export function ComplaintSummaryPanel({
  complaints,
  isLoading,
  error,
  onRetry,
}: ComplaintSummaryPanelProps) {
  const navigate = useNavigate();

  const total = complaints?.correlations_total ?? 0;
  const unreviewed = complaints?.correlations_unreviewed ?? 0;

  return (
    <Card
      title="Complaints"
      description="Cybercrime complaints reported in the window, and the state of their correlations."
      actions={
        <button
          type="button"
          onClick={() => navigate(paths.complaints)}
          className="text-2xs font-medium text-accent-700 hover:underline dark:text-accent-300"
        >
          All complaints
        </button>
      }
    >
      <KeyValueList
        columns={2}
        entries={[
          {
            label: 'Reported in window',
            value: formatCount(complaints?.reported_in_window ?? 0),
            help: 'By the date the complaint was reported, not the date it was loaded into MuleGuard.',
          },
          {
            label: 'Complaints held',
            value: formatCount(complaints?.total_all_time ?? 0),
            help: 'All complaints in the system, regardless of window.',
          },
          {
            label: 'Deterministic links',
            value: formatCount(complaints?.correlations_deterministic ?? 0),
            help: 'Tier 1-2: the complaint names a reference that exists. An identity, so no confidence value applies.',
          },
          {
            label: 'Inferred links',
            value: formatCount(complaints?.correlations_inferred ?? 0),
            help: 'Tier 3-5: matched through an entity, the network or narrative text. Each carries a confidence and is a lead until reviewed.',
          },
          {
            label: 'Unreviewed',
            value:
              total > 0
                ? `${formatCount(unreviewed)} (${formatPercent(unreviewed / total)})`
                : formatCount(unreviewed),
            help: 'Nobody has accepted or rejected these yet.',
            wide: true,
          },
        ]}
      />

      <div className="mt-4 border-t border-ink-200 pt-3 dark:border-ink-700">
        <ComplaintsByCategoryChart
          data={toCategoryCounts(complaints?.by_category)}
          isLoading={isLoading}
          error={error}
          onRetry={onRetry}
          height={200}
          onSelectCategory={(category) =>
            navigate(`${paths.complaints}?category=${encodeURIComponent(category)}`)
          }
        />
      </div>
    </Card>
  );
}
