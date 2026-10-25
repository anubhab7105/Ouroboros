import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';

import { Button } from '@/components/common/Button';
import { Card } from '@/components/common/Card';
import { EmptyState } from '@/components/common/EmptyState';
import { ErrorState } from '@/components/common/ErrorState';
import { FormField } from '@/components/common/FormField';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { Pagination } from '@/components/common/Pagination';
import { TextArea } from '@/components/common/TextArea';
import { RoleGate } from '@/components/layout/RoleGate';
import { useApiError } from '@/hooks/useApiError';
import { formatDateTime, formatRelative } from '@/lib/dates';
import { truncateId } from '@/lib/formatters';
import { PERMISSIONS } from '@/lib/permissions';
import { queryKeys } from '@/lib/queryKeys';
import { pageInfo } from '@/types/common';

import { addCaseNote, fetchCaseNotes } from './casesApi';

export interface CaseNotesPanelProps {
  caseId: string;
}

/**
 * The investigator's notes.
 *
 * Notes are append-only: the API offers no edit and no delete, and this panel
 * offers neither either. That is the right design for an investigative record
 * — a note that could be rewritten after the fact is worth little — and the
 * form says so before someone commits a note they would rather have phrased
 * differently.
 *
 * The newest note is shown first, which is the opposite of a chat log and the
 * right order for someone picking up a case they have not read.
 */
export function CaseNotesPanel({ caseId }: CaseNotesPanelProps) {
  const queryClient = useQueryClient();
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [draft, setDraft] = useState('');
  const [submitted, setSubmitted] = useState(false);

  const query = useQuery({
    queryKey: queryKeys.cases.notes(caseId, page),
    queryFn: () =>
      fetchCaseNotes(caseId, {
        page,
        page_size: pageSize,
        sort_by: 'created_at',
        sort_order: 'desc',
      }),
  });

  const mutation = useMutation({
    mutationFn: () => addCaseNote(caseId, { note: draft.trim() }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.cases.all });
      setDraft('');
      setSubmitted(false);
      setPage(1);
    },
  });

  const error = useApiError(query.error ?? mutation.error);
  const notes = query.data?.items ?? [];

  return (
    <Card
      title="Notes"
      description="Append-only. A note cannot be edited or deleted once written, here or anywhere else."
      caveats={query.data?.caveats}
    >
      <RoleGate permissions={[PERMISSIONS.addCaseNote]} silent>
        <form
          className="mb-4"
          onSubmit={(event) => {
            event.preventDefault();
            setSubmitted(true);
            if (draft.trim()) mutation.mutate();
          }}
        >
          <FormField
            label="Add a note"
            hint="Permanent, attributed to you, and visible to anyone who can read this case."
            error={submitted && !draft.trim() ? 'Write something before saving.' : undefined}
          >
            {({ id, describedBy, invalid }) => (
              <TextArea
                id={id}
                aria-describedby={describedBy}
                invalid={invalid}
                value={draft}
                onChange={(event) => setDraft(event.target.value)}
                rows={3}
                maxLength={4000}
                showCount
                placeholder="What you found, and what you concluded from it."
              />
            )}
          </FormField>

          <div className="mt-2 flex items-center gap-2">
            <Button type="submit" size="sm" variant="primary" isLoading={mutation.isPending}>
              Save note
            </Button>
            {draft.trim() ? (
              <Button
                type="button"
                size="sm"
                variant="ghost"
                onClick={() => setDraft('')}
                disabled={mutation.isPending}
              >
                Discard draft
              </Button>
            ) : null}
          </div>
        </form>
      </RoleGate>

      {error ? <ErrorState error={error} onRetry={() => void query.refetch()} compact /> : null}

      {query.isLoading ? (
        <LoadingSpinner label="Loading notes" />
      ) : notes.length === 0 ? (
        <EmptyState
          title="No notes yet"
          message="The reasoning behind a disposition belongs here. A case closed with no notes is one nobody can review."
          compact
        />
      ) : (
        <>
          <ol className="space-y-3">
            {notes.map((note) => (
              <li
                key={note.id}
                className="rounded-md border border-ink-200 p-3 dark:border-ink-700"
              >
                <p className="whitespace-pre-line text-xs leading-relaxed text-ink-800 dark:text-ink-100">
                  {note.summary ?? '(empty note)'}
                </p>
                <p className="mt-1.5 text-2xs text-ink-500 dark:text-ink-400">
                  {note.actor_username ?? (note.actor_id ? truncateId(note.actor_id, 6) : 'Unknown')}
                  {' · '}
                  <span title={formatDateTime(note.created_at)}>
                    {formatRelative(note.created_at)}
                  </span>
                </p>
              </li>
            ))}
          </ol>

          {query.data ? (
            <Pagination
              meta={pageInfo(query.data)!}
              onPageChange={setPage}
              onPageSizeChange={setPageSize}
              requestedPageSize={pageSize}
              className="mt-3 border-t-0 px-0"
            />
          ) : null}
        </>
      )}
    </Card>
  );
}
