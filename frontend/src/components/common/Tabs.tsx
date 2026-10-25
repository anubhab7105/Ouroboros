import clsx from 'clsx';
import { useId, type ReactNode } from 'react';

export interface TabItem {
  id: string;
  label: string;
  /** Shown as a count beside the label. */
  badge?: number | string;
  disabled?: boolean;
  content: ReactNode;
}

export interface TabsProps {
  items: TabItem[];
  activeId: string;
  onChange: (id: string) => void;
  className?: string;
}

/**
 * A tab strip.
 *
 * Arrow-key navigation follows the ARIA tabs pattern, which is how a keyboard
 * user expects to move between the panels on an account or case page.
 *
 * Only the active panel is rendered. On the account page each tab is a
 * separate query, and mounting all of them would fire six requests for data
 * the analyst may never look at.
 */
export function Tabs({ items, activeId, onChange, className }: TabsProps) {
  const baseId = useId();
  const enabled = items.filter((item) => !item.disabled);
  const active = items.find((item) => item.id === activeId) ?? items[0];

  const move = (direction: 1 | -1) => {
    const index = enabled.findIndex((item) => item.id === activeId);
    if (index === -1) return;

    const next = enabled[(index + direction + enabled.length) % enabled.length];
    if (next) onChange(next.id);
  };

  return (
    <div className={className}>
      <div
        role="tablist"
        className="flex items-center gap-0.5 overflow-x-auto border-b border-ink-200 dark:border-ink-700"
        onKeyDown={(event) => {
          if (event.key === 'ArrowRight') {
            event.preventDefault();
            move(1);
          } else if (event.key === 'ArrowLeft') {
            event.preventDefault();
            move(-1);
          }
        }}
      >
        {items.map((item) => {
          const selected = item.id === active?.id;

          return (
            <button
              key={item.id}
              type="button"
              role="tab"
              id={`${baseId}-tab-${item.id}`}
              aria-selected={selected}
              aria-controls={`${baseId}-panel-${item.id}`}
              tabIndex={selected ? 0 : -1}
              disabled={item.disabled}
              onClick={() => onChange(item.id)}
              className={clsx(
                'whitespace-nowrap border-b-2 px-3 py-2 text-xs font-medium transition-colors duration-fast',
                selected
                  ? 'border-accent-600 text-accent-800 dark:border-accent-400 dark:text-accent-200'
                  : 'border-transparent text-ink-600 hover:text-ink-900 dark:text-ink-400 dark:hover:text-ink-100',
                item.disabled && 'cursor-not-allowed opacity-50',
              )}
            >
              {item.label}
              {item.badge !== undefined && item.badge !== null ? (
                <span className="ml-1.5 rounded bg-ink-100 px-1 py-0.5 text-2xs tabular text-ink-600 dark:bg-ink-800 dark:text-ink-300">
                  {item.badge}
                </span>
              ) : null}
            </button>
          );
        })}
      </div>

      {active ? (
        <div
          role="tabpanel"
          id={`${baseId}-panel-${active.id}`}
          aria-labelledby={`${baseId}-tab-${active.id}`}
          tabIndex={0}
          className="pt-4"
        >
          {active.content}
        </div>
      ) : null}
    </div>
  );
}
