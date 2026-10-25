import { useNavigate } from 'react-router-dom';

import { KpiCard } from '@/components/charts/KpiCard';
import { formatCount } from '@/lib/amounts';
import { paths } from '@/routes/paths';
import type { DashboardOverview } from '@/types/dashboard';

export interface SummaryCardsProps {
  overview?: DashboardOverview;
  isLoading?: boolean;
}

/**
 * The headline numbers.
 *
 * Which six, and why these:
 *
 * - **Open alerts** and **unassigned** are separated. A queue of 400 with an
 *   owner each is a workload; 400 with no owner is a backlog nobody is
 *   touching, and only the second needs someone's attention today.
 *
 * - **Assessments in window** is here rather than buried, because it is the
 *   denominator for everything else. Zero assessments with zero alerts means
 *   nothing was analysed, which looks identical to "nothing was found" unless
 *   this number is on screen.
 *
 * - **Unreviewed correlations** is the complaint-side backlog, which has no
 *   other home on this page.
 *
 * Each card states its definition, and each links to the filtered list that
 * produced it so the number is checkable rather than asserted.
 */
export function SummaryCards({ overview, isLoading }: SummaryCardsProps) {
  const navigate = useNavigate();

  const alerts = overview?.alerts;
  const cases = overview?.cases;
  const complaints = overview?.complaints;
  const assessments = overview?.assessments;

  // The endpoint breaks *open* alerts down by state and *window* alerts down
  // by priority. Each card uses whichever breakdown actually answers it, and
  // says in its definition which population it counted — deriving one from the
  // other would produce a number that looks precise and is not.
  const criticalInWindow = alerts?.created_by_priority?.CRITICAL ?? 0;
  const awaitingTriage = alerts?.open_by_state?.NEW ?? 0;

  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
      <KpiCard
        label="Open alerts"
        value={alerts?.open_all_time ?? null}
        isLoading={isLoading}
        definition="Alerts not yet closed, across all time rather than the selected window. An alert raised two months ago and still open is still work."
        emphasis={(alerts?.open_all_time ?? 0) > 0 ? 'attention' : 'none'}
        onClick={() => navigate(`${paths.alerts}?open_only=true`)}
        actionLabel="Open alerts: show the open alert queue"
      />

      <KpiCard
        label="Awaiting triage"
        value={alerts ? awaitingTriage : null}
        isLoading={isLoading}
        definition="Open alerts in the NEW state — nobody has acknowledged or taken them. This is the queue that grows when nobody is watching."
        emphasis={awaitingTriage > 0 ? 'critical' : 'none'}
        onClick={() => navigate(`${paths.alerts}?open_only=true&unassigned_only=true`)}
        actionLabel="Awaiting triage: show unassigned open alerts"
      />

      <KpiCard
        label="Critical in window"
        value={alerts ? criticalInWindow : null}
        isLoading={isLoading}
        definition="Alerts created in the selected window with CRITICAL priority. Critical means several typologies corroborated each other, not that fraud is proven."
        emphasis={criticalInWindow > 0 ? 'critical' : 'none'}
        onClick={() => navigate(`${paths.alerts}?priority=CRITICAL`)}
        actionLabel="Critical alerts: show the critical queue"
      />

      <KpiCard
        label="Open cases"
        value={cases?.open_all_time ?? null}
        isLoading={isLoading}
        definition="Investigations not yet closed. A case is opened from an alert when an analyst decides the lead is worth working."
        detail={
          cases?.open_by_status?.ESCALATED
            ? `${formatCount(cases.open_by_status.ESCALATED)} escalated`
            : undefined
        }
        onClick={() => navigate(`${paths.cases}?open_only=true`)}
        actionLabel="Open cases: show open investigations"
      />

      <KpiCard
        label="Assessed in window"
        value={assessments?.total_in_window ?? null}
        isLoading={isLoading}
        definition="Assessments persisted in the window. If this is zero, nothing was analysed — an empty alert queue then means the analysis did not run, not that nothing was found."
        detail={
          assessments?.total_in_window === 0 && !isLoading ? 'No analysis ran in this window' : undefined
        }
        emphasis={assessments && assessments.total_in_window === 0 ? 'attention' : 'none'}
        onClick={() => navigate(paths.ingestion)}
        actionLabel="Assessments: go to the Data page to start an analysis run"
      />

      <KpiCard
        label="Unreviewed links"
        value={complaints?.correlations_unreviewed ?? null}
        isLoading={isLoading}
        definition="Complaint correlations nobody has accepted or rejected. Inferred correlations are leads until a human confirms them, so an unreviewed backlog is unverified evidence."
        detail={
          complaints
            ? `${formatCount(complaints.correlations_deterministic)} deterministic, ${formatCount(
                complaints.correlations_inferred,
              )} inferred`
            : undefined
        }
        emphasis={(complaints?.correlations_unreviewed ?? 0) > 0 ? 'attention' : 'none'}
        onClick={() => navigate(`${paths.complaints}?review_state=UNREVIEWED`)}
        actionLabel="Unreviewed correlations: show complaints with unreviewed links"
      />
    </div>
  );
}
