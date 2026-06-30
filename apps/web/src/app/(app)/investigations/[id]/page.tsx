"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import { Can } from "@/components/can";
import { DataTable } from "@/components/data-table";
import { ErrorState, LoadingState, PageHeader } from "@/components/states";
import { SeverityBadge } from "@/components/severity-badge";
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
import type {
  InvestigationDetail,
  LinkedFinding,
  TimelineEntry,
} from "@/lib/types";
import { formatDateTime } from "@/lib/utils";

const STATUS_OPTIONS = [
  { value: "open", label: "Open" },
  { value: "in_progress", label: "In progress" },
  { value: "pending_review", label: "Pending review" },
  { value: "closed", label: "Closed" },
];

const MODULE_OPTIONS = [
  { value: "dlm", label: "DLM" },
  { value: "clm", label: "CLM" },
  { value: "dwm", label: "DWM" },
  { value: "brm", label: "BRM" },
  { value: "phm", label: "PHM" },
];

const linkedFindingColumns: ColumnDef<LinkedFinding, unknown>[] = [
  {
    accessorKey: "source_module",
    header: "Module",
    cell: ({ row }) => (
      <span className="uppercase text-muted-foreground">
        {row.original.source_module}
      </span>
    ),
  },
  {
    accessorKey: "source_finding_id",
    header: "Finding ID",
    cell: ({ row }) => (
      <span className="font-mono text-xs">{row.original.source_finding_id}</span>
    ),
  },
  {
    accessorKey: "notes",
    header: "Notes",
    cell: ({ row }) => (
      <span className="text-muted-foreground">{row.original.notes || "—"}</span>
    ),
  },
  {
    accessorKey: "linked_at",
    header: "Linked",
    cell: ({ row }) => (
      <span className="text-muted-foreground">
        {formatDateTime(row.original.linked_at)}
      </span>
    ),
  },
];

function Timeline({ entries }: { entries: TimelineEntry[] }) {
  if (entries.length === 0) {
    return <p className="text-sm text-muted-foreground">No timeline entries yet.</p>;
  }
  const sorted = [...entries].sort(
    (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
  );
  return (
    <ol className="space-y-4 border-l pl-4">
      {sorted.map((entry) => (
        <li key={entry.id} className="relative">
          <span className="absolute -left-[1.4rem] top-1 h-2.5 w-2.5 rounded-full bg-primary" />
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-medium">
              {entry.entry_type.replace(/_/g, " ")}
            </span>
            <span className="text-xs text-muted-foreground">
              {formatDateTime(entry.created_at)}
            </span>
          </div>
          {entry.detail ? (
            <p className="mt-1 text-sm text-muted-foreground">{entry.detail}</p>
          ) : null}
        </li>
      ))}
    </ol>
  );
}

export default function InvestigationDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const queryClient = useQueryClient();

  const detailQuery = useQuery({
    queryKey: ["investigations", "detail", id],
    queryFn: () => apiFetch<InvestigationDetail>(`/api/investigations/${id}`),
    enabled: Boolean(id),
  });

  const timelineQuery = useQuery({
    queryKey: ["investigations", "timeline", id],
    queryFn: () => apiFetch<TimelineEntry[]>(`/api/investigations/${id}/timeline`),
    enabled: Boolean(id),
  });

  const [statusValue, setStatusValue] = useState("");
  const [note, setNote] = useState("");
  const [linkModule, setLinkModule] = useState("dlm");
  const [linkFindingId, setLinkFindingId] = useState("");

  function invalidate() {
    void queryClient.invalidateQueries({ queryKey: ["investigations", "detail", id] });
    void queryClient.invalidateQueries({ queryKey: ["investigations", "timeline", id] });
    void queryClient.invalidateQueries({ queryKey: ["investigations", "list"] });
  }

  const statusMutation = useMutation({
    mutationFn: (status: string) =>
      apiFetch(`/api/investigations/${id}/status`, {
        method: "PATCH",
        body: JSON.stringify({ status }),
      }),
    onSuccess: () => {
      toast.success("Status updated");
      invalidate();
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.message : "Failed to update status"),
  });

  const noteMutation = useMutation({
    mutationFn: (value: string) =>
      apiFetch(`/api/investigations/${id}/notes`, {
        method: "POST",
        body: JSON.stringify({ note: value }),
      }),
    onSuccess: () => {
      toast.success("Note added");
      setNote("");
      invalidate();
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.message : "Failed to add note"),
  });

  const linkMutation = useMutation({
    mutationFn: (vars: { source_module: string; source_finding_id: string }) =>
      apiFetch(`/api/investigations/${id}/findings`, {
        method: "POST",
        body: JSON.stringify(vars),
      }),
    onSuccess: () => {
      toast.success("Finding linked");
      setLinkFindingId("");
      invalidate();
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.message : "Failed to link finding"),
  });

  const closeMutation = useMutation({
    mutationFn: () =>
      apiFetch(`/api/investigations/${id}/close`, { method: "POST" }),
    onSuccess: () => {
      toast.success("Investigation closed");
      invalidate();
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.message : "Failed to close investigation"),
  });

  if (detailQuery.isLoading) {
    return <LoadingState label="Loading investigation…" />;
  }

  if (detailQuery.isError || !detailQuery.data) {
    return (
      <div className="space-y-4">
        <Link
          href="/investigations"
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4" /> Back to investigations
        </Link>
        <ErrorState onRetry={() => void detailQuery.refetch()} />
      </div>
    );
  }

  const inv = detailQuery.data;

  function onAddNote(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!note.trim()) {
      toast.error("Note cannot be empty");
      return;
    }
    noteMutation.mutate(note.trim());
  }

  function onLinkFinding(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!linkFindingId.trim()) {
      toast.error("Finding ID is required");
      return;
    }
    linkMutation.mutate({
      source_module: linkModule,
      source_finding_id: linkFindingId.trim(),
    });
  }

  return (
    <div className="space-y-6">
      <Link
        href="/investigations"
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" /> Back to investigations
      </Link>

      <PageHeader
        title={inv.title}
        description={inv.description || undefined}
        actions={
          <Can permission="investigation:update">
            <Button
              variant="destructive"
              disabled={inv.status === "closed" || closeMutation.isPending}
              onClick={() => closeMutation.mutate()}
            >
              {closeMutation.isPending ? "Closing…" : "Close"}
            </Button>
          </Can>
        }
      />

      <div className="flex flex-wrap items-center gap-6 text-sm">
        <div className="flex items-center gap-2">
          <span className="text-muted-foreground">Status</span>
          <StatusBadge status={inv.status} />
        </div>
        <div className="flex items-center gap-2">
          <span className="text-muted-foreground">Priority</span>
          <SeverityBadge severity={inv.priority} />
        </div>
        <div className="flex items-center gap-2">
          <span className="text-muted-foreground">Assignee</span>
          <span>{inv.assigned_to || "Unassigned"}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-muted-foreground">Created</span>
          <span>{formatDateTime(inv.created_at)}</span>
        </div>
      </div>

      <Can permission="investigation:update">
        <div className="grid gap-4 md:grid-cols-3">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Update status</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <Select
                value={statusValue || inv.status}
                onChange={(e) => setStatusValue(e.target.value)}
              >
                {STATUS_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </Select>
              <Button
                size="sm"
                disabled={statusMutation.isPending}
                onClick={() => statusMutation.mutate(statusValue || inv.status)}
              >
                {statusMutation.isPending ? "Saving…" : "Save status"}
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Add note</CardTitle>
            </CardHeader>
            <CardContent>
              <form className="space-y-3" onSubmit={onAddNote}>
                <Input
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  placeholder="Add an investigation note"
                />
                <Button size="sm" type="submit" disabled={noteMutation.isPending}>
                  {noteMutation.isPending ? "Adding…" : "Add note"}
                </Button>
              </form>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Link finding</CardTitle>
            </CardHeader>
            <CardContent>
              <form className="space-y-3" onSubmit={onLinkFinding}>
                <Select
                  value={linkModule}
                  onChange={(e) => setLinkModule(e.target.value)}
                >
                  {MODULE_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </Select>
                <Input
                  value={linkFindingId}
                  onChange={(e) => setLinkFindingId(e.target.value)}
                  placeholder="Source finding ID"
                />
                <Button size="sm" type="submit" disabled={linkMutation.isPending}>
                  {linkMutation.isPending ? "Linking…" : "Link"}
                </Button>
              </form>
            </CardContent>
          </Card>
        </div>
      </Can>

      <Card>
        <CardHeader>
          <CardTitle>Linked findings</CardTitle>
          <CardDescription>Findings associated with this investigation.</CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={linkedFindingColumns}
            rows={inv.linked_findings ?? []}
            emptyMessage="No findings linked yet."
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Timeline</CardTitle>
          <CardDescription>Chronological activity on this case.</CardDescription>
        </CardHeader>
        <CardContent>
          {timelineQuery.isError ? (
            <ErrorState onRetry={() => void timelineQuery.refetch()} />
          ) : (
            <Timeline
              entries={
                timelineQuery.data ?? inv.timeline ?? []
              }
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
