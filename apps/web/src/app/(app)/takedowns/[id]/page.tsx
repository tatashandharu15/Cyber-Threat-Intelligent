"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";
import { Can } from "@/components/can";
import { ErrorState, LoadingState, PageHeader } from "@/components/states";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { apiFetch, ApiError } from "@/lib/api";
import type { Takedown, TakedownEvent, TakedownStatus } from "@/lib/types";
import { formatDateTime } from "@/lib/utils";

// Valid next statuses keyed by current status (mirrors backend state machine).
const NEXT_STATUSES: Record<TakedownStatus, TakedownStatus[]> = {
  draft: [],
  submitted: ["acknowledged", "rejected"],
  acknowledged: ["actioned", "rejected"],
  actioned: ["closed"],
  rejected: ["closed"],
  closed: [],
};

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div className="space-y-1">
      <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="break-all text-sm">{value || "—"}</p>
    </div>
  );
}

export default function TakedownDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const queryClient = useQueryClient();

  const detailQuery = useQuery({
    queryKey: ["takedowns", "detail", id],
    queryFn: () => apiFetch<Takedown>(`/api/takedowns/${id}`),
    enabled: Boolean(id),
  });

  const eventsQuery = useQuery({
    queryKey: ["takedowns", "events", id],
    queryFn: () => apiFetch<TakedownEvent[]>(`/api/takedowns/${id}/events`),
    enabled: Boolean(id),
  });

  const [nextStatus, setNextStatus] = useState<TakedownStatus | "">("");
  const [operatorResponse, setOperatorResponse] = useState("");

  function invalidate() {
    void queryClient.invalidateQueries({ queryKey: ["takedowns", "detail", id] });
    void queryClient.invalidateQueries({ queryKey: ["takedowns", "events", id] });
    void queryClient.invalidateQueries({ queryKey: ["takedowns", "list"] });
  }

  const submitMutation = useMutation({
    mutationFn: () => apiFetch(`/api/takedowns/${id}/submit`, { method: "POST" }),
    onSuccess: () => {
      toast.success("Takedown submitted");
      invalidate();
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.message : "Failed to submit takedown"),
  });

  const statusMutation = useMutation({
    mutationFn: (vars: { status: TakedownStatus; operator_response?: string }) =>
      apiFetch(`/api/takedowns/${id}/status`, {
        method: "PATCH",
        body: JSON.stringify(vars),
      }),
    onSuccess: () => {
      toast.success("Status updated");
      setNextStatus("");
      setOperatorResponse("");
      invalidate();
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.message : "Failed to update status"),
  });

  if (detailQuery.isLoading) {
    return <LoadingState label="Loading takedown…" />;
  }

  if (detailQuery.isError || !detailQuery.data) {
    return (
      <div className="space-y-4">
        <Link
          href="/takedowns"
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4" /> Back to takedowns
        </Link>
        <ErrorState onRetry={() => void detailQuery.refetch()} />
      </div>
    );
  }

  const td = detailQuery.data;
  const allowedNext = NEXT_STATUSES[td.status as TakedownStatus] ?? [];
  const events = [...(eventsQuery.data ?? [])].sort(
    (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
  );

  return (
    <div className="space-y-6">
      <Link
        href="/takedowns"
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" /> Back to takedowns
      </Link>

      <PageHeader
        title={`Takedown ${td.id.slice(0, 8)}`}
        description={td.submission_target}
        actions={
          <div className="flex items-center gap-2">
            <StatusBadge status={td.status} />
            <Can permission="takedown:update">
              {td.status === "draft" ? (
                <Button
                  disabled={submitMutation.isPending}
                  onClick={() => submitMutation.mutate()}
                >
                  {submitMutation.isPending ? "Submitting…" : "Submit"}
                </Button>
              ) : null}
            </Can>
          </div>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle>Details</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Detail label="Source module" value={td.source_module.toUpperCase()} />
          <Detail label="Source finding" value={td.source_finding_id} />
          <Detail label="Target" value={td.submission_target} />
          <Detail
            label="Target type"
            value={td.submission_target_type.replace(/_/g, " ")}
          />
          <Detail label="Evidence ref" value={td.evidence_package_ref} />
          <Detail label="Operator response" value={td.operator_response || ""} />
          <Detail label="Created" value={formatDateTime(td.created_at)} />
          <Detail
            label="Submitted"
            value={td.submitted_at ? formatDateTime(td.submitted_at) : ""}
          />
          <Detail
            label="Closed"
            value={td.closed_at ? formatDateTime(td.closed_at) : ""}
          />
        </CardContent>
      </Card>

      {allowedNext.length > 0 ? (
        <Can permission="takedown:update">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Transition status</CardTitle>
              <CardDescription>
                Move this takedown to its next lifecycle state.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="td-next">Next status</Label>
                  <Select
                    id="td-next"
                    value={nextStatus}
                    onChange={(e) =>
                      setNextStatus(e.target.value as TakedownStatus | "")
                    }
                  >
                    <option value="">Select status…</option>
                    {allowedNext.map((s) => (
                      <option key={s} value={s}>
                        {s.charAt(0).toUpperCase() + s.slice(1)}
                      </option>
                    ))}
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="td-response">Operator response (optional)</Label>
                  <Input
                    id="td-response"
                    value={operatorResponse}
                    onChange={(e) => setOperatorResponse(e.target.value)}
                    placeholder="Notes from the operator"
                  />
                </div>
              </div>
              <Button
                size="sm"
                disabled={!nextStatus || statusMutation.isPending}
                onClick={() => {
                  if (!nextStatus) return;
                  statusMutation.mutate({
                    status: nextStatus,
                    ...(operatorResponse.trim()
                      ? { operator_response: operatorResponse.trim() }
                      : {}),
                  });
                }}
              >
                {statusMutation.isPending ? "Saving…" : "Apply transition"}
              </Button>
            </CardContent>
          </Card>
        </Can>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Event chain</CardTitle>
          <CardDescription>Immutable audit trail for this takedown.</CardDescription>
        </CardHeader>
        <CardContent>
          {eventsQuery.isLoading ? (
            <LoadingState label="Loading events…" />
          ) : eventsQuery.isError ? (
            <ErrorState onRetry={() => void eventsQuery.refetch()} />
          ) : events.length === 0 ? (
            <p className="text-sm text-muted-foreground">No events recorded.</p>
          ) : (
            <ol className="space-y-4 border-l pl-4">
              {events.map((ev) => (
                <li key={ev.id} className="relative">
                  <span className="absolute -left-[1.4rem] top-1 h-2.5 w-2.5 rounded-full bg-primary" />
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-medium">
                      {ev.event_type.replace(/_/g, " ")}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {formatDateTime(ev.created_at)}
                    </span>
                  </div>
                  {ev.detail ? (
                    <p className="mt-1 text-sm text-muted-foreground">{ev.detail}</p>
                  ) : null}
                </li>
              ))}
            </ol>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
