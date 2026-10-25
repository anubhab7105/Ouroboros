import clsx from 'clsx';
import { NavLink } from 'react-router-dom';

import { usePermission } from '@/hooks/usePermission';
import { PERMISSIONS, type Permission } from '@/lib/permissions';
import { paths } from '@/routes/paths';

interface NavItem {
  to: string;
  label: string;
  /** Any one of these admits the item. */
  permissions: Array<Permission | string>;
  /** Short gloss shown on hover and read by assistive tech. */
  hint: string;
}

interface NavGroup {
  id: string;
  label: string;
  items: NavItem[];
}

/**
 * Navigation grouped by how an investigation actually proceeds, not by data
 * model. "Investigate" holds the work queue; "Explore" holds the places you
 * go to answer a question raised by that queue; "Operate" is for the people
 * who keep the platform fed and audited.
 */
const NAV_GROUPS: NavGroup[] = [
  {
    id: 'investigate',
    label: 'Investigate',
    items: [
      {
        to: paths.dashboard,
        label: 'Dashboard',
        permissions: [PERMISSIONS.readDashboard],
        hint: 'Queue sizes, recent activity and model status',
      },
      {
        to: paths.alerts,
        label: 'Alerts',
        permissions: [],
        hint: 'Risk findings awaiting triage',
      },
      {
        to: paths.cases,
        label: 'Cases',
        permissions: [],
        hint: 'Investigations with evidence and a disposition',
      },
    ],
  },
  {
    id: 'explore',
    label: 'Explore',
    items: [
      {
        to: paths.accounts,
        label: 'Accounts',
        permissions: [],
        hint: 'Accounts with their latest risk assessment',
      },
      {
        to: paths.transactions,
        label: 'Transactions',
        permissions: [],
        hint: 'Transaction ledger with filters',
      },
      {
        to: paths.graph,
        label: 'Network',
        permissions: [],
        hint: 'Fund flows and shared identifiers between accounts',
      },
      {
        to: paths.complaints,
        label: 'Complaints',
        permissions: [],
        hint: 'Cybercrime complaints and their correlations',
      },
    ],
  },
  {
    id: 'operate',
    label: 'Operate',
    items: [
      {
        to: paths.reports,
        label: 'Reports',
        permissions: [],
        hint: 'Case report packs for referral',
      },
      {
        to: paths.modelMonitoring,
        label: 'Model',
        permissions: [],
        hint: 'Active model version, metrics and stated limitations',
      },
      {
        to: paths.ingestion,
        label: 'Data',
        permissions: [PERMISSIONS.runIngestion, PERMISSIONS.runAnalysis],
        hint: 'Load data and start analysis runs',
      },
      {
        to: paths.audit,
        label: 'Audit trail',
        permissions: [PERMISSIONS.readAudit],
        hint: 'Who did what, and when',
      },
    ],
  },
];

export interface SidebarProps {
  collapsed: boolean;
  /** Mobile drawer: when set, the sidebar is overlaid and dismissable. */
  onNavigate?: () => void;
  className?: string;
}

/**
 * Primary navigation.
 *
 * Items the user has no permission for are omitted rather than disabled. A
 * whole section they can never open is not a useful thing to leave on screen;
 * for individual actions inside a page the opposite choice is made (see
 * `RoleGate`), because there the control's absence would be confusing.
 */
export function Sidebar({ collapsed, onNavigate, className }: SidebarProps) {
  const { canAny } = usePermission();

  const groups = NAV_GROUPS.map((group) => ({
    ...group,
    items: group.items.filter((item) => canAny(item.permissions)),
  })).filter((group) => group.items.length > 0);

  return (
    <nav
      aria-label="Main navigation"
      className={clsx(
        'flex h-full flex-col gap-5 overflow-y-auto border-r border-ink-200 bg-white px-3 py-4',
        'dark:border-ink-700 dark:bg-ink-900',
        collapsed ? 'w-16' : 'w-56',
        className,
      )}
    >
      {groups.map((group) => (
        <div key={group.id}>
          {!collapsed ? (
            <p className="mb-1.5 px-2 text-2xs font-semibold uppercase tracking-wider text-ink-400 dark:text-ink-500">
              {group.label}
            </p>
          ) : (
            <hr className="mb-2 border-ink-200 dark:border-ink-700" />
          )}

          <ul className="space-y-0.5">
            {group.items.map((item) => (
              <li key={item.to}>
                <NavLink
                  to={item.to}
                  onClick={onNavigate}
                  title={collapsed ? `${item.label} — ${item.hint}` : item.hint}
                  className={({ isActive }) =>
                    clsx(
                      'flex items-center gap-2 rounded-md px-2 py-1.5 text-xs font-medium transition-colors duration-fast',
                      collapsed && 'justify-center',
                      isActive
                        ? 'bg-accent-100 text-accent-900 dark:bg-accent-900/50 dark:text-accent-100'
                        : 'text-ink-700 hover:bg-ink-100 dark:text-ink-200 dark:hover:bg-ink-800',
                    )
                  }
                >
                  {collapsed ? (
                    <>
                      <span aria-hidden="true" className="text-sm font-semibold">
                        {item.label.slice(0, 1)}
                      </span>
                      <span className="mg-visually-hidden">{item.label}</span>
                    </>
                  ) : (
                    item.label
                  )}
                </NavLink>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </nav>
  );
}
