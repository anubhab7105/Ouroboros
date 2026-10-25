import { Link } from 'react-router-dom';

import { Badge } from '@/components/common/Badge';
import { Card } from '@/components/common/Card';
import { EmptyState } from '@/components/common/EmptyState';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { SeverityBadge } from '@/components/common/SeverityBadge';
import { StatusPill } from '@/components/common/StatusPill';
import { formatCount, formatScore } from '@/lib/amounts';
import { formatDuration } from '@/lib/dates';
import { truncateId, truncateText } from '@/lib/formatters';
import { paths } from '@/routes/paths';
import type { DashboardQueueItem, DashboardQueueSection, DashboardQueues } from '@/types/dashboard';

export interface ActivityFeedProps {
  queues?: DashboardQueues;
  isLoading?: boolean;
  /** Username of the signed-in analyst, for the "mine" heading. */
  username?: string;
}

interface SectionSpec {
  key: keyof Omit<DashboardQueues, 'generated_at' | 'caveats'>;
  heading: string;
  /** Why this queue matters, shown under the heading. */
  rationale: string;
  link: string;
  kind: 'alert' | 'case' | 'correlation';
}

const SECTIONS: SectionSpec[] = [
  {
    key: 'unassigned_alerts',
    heading: 'Unassigned alerts',
    rationale: 'Nobody owns these. They do not age out on their own.',
    link: `${paths.alerts}?open_only=true&unassigned_only=true`,
    kind: 'alert',
  },
  {
    key: 'my_alerts',
    heading: 'Assigned to me',
    rationale: 'Alerts you have taken and not yet closed.',
    link: `${paths.alerts}?open_only=true`,
    kind: 'alert',
  },
  {
    key: 'escalated_cases',
    heading: 'Escalated cases',
    rationale: 'Waiting on a senior investigator.',
    link: `${paths.cases}?status=ESCALATED`,
    kind: 'case',
  },
  {
    key: 'under_investigation_cases',
    heading: 'Cases under investigation',
    rationale: 'In progress, with an owner.',
    link: `${paths.cases}?status=UNDER_INVESTIGATION`,
    kind: 'case',
  },
  {
    key: 'triaged_cases',
    heading: 'Triaged cases',
    rationale: 'Assigned to someone who has not started yet.',
    link: `${paths.cases}?status=TRIAGED`,
    kind: 'case',
  },
  {
    key: 'new_cases',
    heading: 'New cases',
    rationale: 'Opened, unassigned, not yet started.',
    link: `${paths.cases}?status=NEW`,
    kind: 'case',
  },
  {
    key: 'unreviewed_complaint_correlations',
    heading: 'Unreviewed complaint links',
    rationale: 'Inferred links waiting for someone to accept or reject them.',
    link: `${paths.complaints}?review_state=UNREVIEWED`,
    kind: 'correlation',
  },
];

function itemHref(item: DashboardQueueItem, kind: SectionSpec['kind']): string {
  if (kind === 'alert') return paths.alert(item.id);
  if (kind === 'case') return paths.case(item.id);
  return `${paths.complaints}?correlation_id=${encodeURIComponent(item.id)}`;
}

function QueueRow({ item, kind }: { item: DashboardQueueItem; kind: SectionSpec['kind'] }) {
  return (
    <li className="flex items-start justify-between gap-3 py-1.5">
      <div className="min-w-0">
        <Link
          to={itemHref(item, kind)}
          className="block truncate text-xs font-medium text-accent-700 hover:underline dark:text-accent-300"
          title={item.title ?? item.id}
        >
          {truncateText(item.title ?? item.id, 58)}
        </Link>

        <p className="mt-0.5 flex flex-wrap items-center gap-x-2 text-2xs text-ink-500 dark:text-ink-400">
          {item.account_id ? (
            <Link
              to={paths.account(item.account_id)}
              className="font-mono hover:underline"
              title={item.account_id}
            >
              {truncateId(item.account_id, 6)}
            </Link>
          ) : null}

          {item.age_seconds !== null && item.age_seconds !== undefined ? (
            <span title="Age, computed server-side so every row agrees on the current time.">
              {formatDuration(item.age_seconds)} old
            </span>
          ) : null}

          {item.score !== null && item.score !== undefined ? (
            <span className="tabular" title="Investigative priority score, 0-100.">
              score {formatScore(item.score)}
            </span>
          ) : null}
        </p>
      </div>

      <div className="flex shrink-0 flex-col items-end gap-1">
        {item.priority ? (
          <SeverityBadge
            severity={(item.priority as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL') ?? null}
          />
        ) : null}
        {item.state ? (
          <StatusPill kind={kind === 'case' ? 'case' : 'alert'} value={item.state} />
        ) : null}
      </div>
    </li>
  );
}

function QueueBlock({
  spec,
  section,
  username,
}: {
  spec: SectionSpec;
  section?: DashboardQueueSection;
  username?: string;
}) {
  const items = section?.items ?? [];
  const heading = spec.key === 'my_alerts' && username ? `Assigned to ${username}` : spec.heading;

  return (
    <div>
      <div className="mb-1 flex items-baseline justify-between gap-2">
        <h3 className="text-2xs font-semibold uppercase tracking-wide text-ink-600 dark:text-ink-300">
          {heading}
        </h3>

        <span className="flex items-center gap-1.5">
          {section?.truncated ? (
            <Badge
              tone="neutral"
              title={`Showing ${items.length} of ${section.total}. The server caps each queue section.`}
            >
              {formatCount(items.length)} of {formatCount(section.total)}
            </Badge>
          ) : (
            <span className="text-2xs tabular text-ink-500 dark:text-ink-400">
              {formatCount(section?.total ?? 0)}
            </span>
          )}

          <Link
            to={spec.link}
            className="text-2xs font-medium text-accent-700 hover:underline dark:text-accent-300"
          >
            Open
          </Link>
        </span>
      </div>

      <p className="mb-1 text-2xs text-ink-500 dark:text-ink-400">{spec.rationale}</p>

      {items.length === 0 ? (
        <p className="py-1.5 text-2xs text-ink-400 dark:text-ink-500">Empty.</p>
      ) : (
        <ul className="divide-y divide-ink-200 dark:divide-ink-700">
          {items.map((item) => (
            <QueueRow key={`${spec.key}-${item.id}`} item={item} kind={spec.kind} />
          ))}
        </ul>
      )}
    </div>
  );
}

/**
 * The work queues.
 *
 * Not a chronological feed of everything that happened — that is the audit
 * trail, and it is a poor way to decide what to do next. This is the set of
 * queues an analyst actually works, ordered by how likely each is to be
 * neglected: unowned work first, then escalations, then work already in
 * progress.
 *
 * Every section states its own total alongside the capped list, because a
 * section showing ten rows out of six hundred is a very different situation
 * from one showing ten out of ten.
 */
export function ActivityFeed({ queues, isLoading, username }: ActivityFeedProps) {
  const hasAnything =
    queues &&
    SECTIONS.some((spec) => (queues[spec.key] as DashboardQueueSection | undefined)?.total);

  return (
    <Card
      title="Work queues"
      description="What is waiting, ordered by how easily it gets forgotten."
      caveats={queues?.caveats}
    >
      {isLoading ? (
        <LoadingSpinner label="Loading queues" />
      ) : !hasAnything ? (
        <EmptyState
          title="Every queue is empty"
          message="If no analysis has run, this is what an un-analysed system looks like rather than a clean one. Check the assessment count above."
          compact
        />
      ) : (
        <div className="space-y-5">
          {SECTIONS.map((spec) => (
            <QueueBlock
              key={spec.key}
              spec={spec}
              section={queues?.[spec.key] as DashboardQueueSection | undefined}
              username={username}
            />
          ))}
        </div>
      )}
    </Card>
  );
}
