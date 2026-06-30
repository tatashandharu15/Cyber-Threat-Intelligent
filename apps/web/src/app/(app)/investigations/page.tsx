"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import { Can } from "@/components/can";
import { DataTable } from "@/components/data-table";
import { PageHeader } from "@/components/states";
import { StatusBadge } from "@/components/status-badge";
import { SeverityBadge } from "@/components/severity-badge";
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
  InboxAlert,
  Investigation,
  InvestigationPriority,
} from "@/lib/types";
import { formatDateTime } from "@/lib/utils";

const STATUS_OPTIONS = [
  { value: "", label: "All statuses" },
  { value: "open", label: "Open" },
  { value: "in_progress", label: "In progress" },
  { value: "pending_review", label: "Pending review" },
  { value: "closed", label: "Closed" },
];

const PRIORITY_OPTIONS = [
  { value: "", label: "All priorities" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

const investigationColumns: ColumnDef<Investigation, unknown>[] = [
  {
    accessorKey: "title",
    header: "Title",
    cell: ({ row }) => (
      <Link
        href={`/investigations/${row.original.id}`}
        className="font-medium text-primary hover:underline"
      >
        {row.original.title}
      </Link>
    ),
  },
  {
    accessorKey: "status",
    header: "Status",
    cell: ({ row }) => <StatusBadge status={row.original.status} />,
  },
  {
    accessorKey: "priority",
    header: "Priority",
    cell: ({ row }) => <SeverityBadge severity={row.original.priority} />,
  },
  {
    accessorKey: "created_at",
    header: "Created",
    cell: ({ row }) => (
      <span className="text-muted-foreground">
        {formatDateTime(row.original.created_at)}
      </span>
    ),
  },
];

function NewInvestigationForm({ onDone }: { onDone: () => void }) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [priority, setPriority] = useState<InvestigationPriority>("medium");

  const mutation = useMutation({
    mutationFn: () =>
      apiFetch<Investigation>("/api/investigations", {
        method: "POST",
        body: JSON.stringify({
          title: title.trim(),
          description: description.trim() || null,
          priority,
        }),
      }),
    onSuccess: (created) => {
      toast.success("Investigation created");
      void queryClient.invalidateQueries({ queryKey: ["investigations"] });
      onDone();
      router.push(`/investigations/${created.id}`);
    },
    onError: (err) => {
      toast.error(err instanceof ApiError ? err.message : "Failed to create investigation");
    },
  });

  function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!title.trim()) {
      toast.error("Title is required");
      return;
    }
    mutation.mutate();
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>New investigation</CardTitle>
        <CardDescription>Open a new case to triage related findings.</CardDescription>
      </CardHeader>
      <CardContent>
        <form className="space-y-4" onSubmit={onSubmit}>
          <div className="space-y-2">
            <Label htmlFor="inv-title">Title</Label>
            <Input
              id="inv-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Suspicious domain campaign"
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="inv-description">Description</Label>
            <Input
              id="inv-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional context"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="inv-priority">Priority</Label>
            <Select
              id="inv-priority"
              value={priority}
              onChange={(e) => setPriority(e.target.value as InvestigationPriority)}
            >
              {PRIORITY_OPTIONS.filter((o) => o.value).map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </Select>
          </div>
          <div className="flex gap-2">
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? "Creating…" : "Create"}
            </Button>
            <Button type="button" variant="outline" onClick={onDone}>
              Cancel
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function LinkInboxAlert({
  alert,
  investigations,
}: {
  alert: InboxAlert;
  investigations: Investigation[];
}) {
  const queryClient = useQueryClient();
  const [target, setTarget] = useState("");

  const mutation = useMutation({
    mutationFn: () =>
      apiFetch(`/api/investigations/${target}/findings`, {
        method: "POST",
        body: JSON.stringify({
          source_module: alert.source_module,
          source_finding_id: alert.source_finding_id,
        }),
      }),
    onSuccess: () => {
      toast.success("Finding linked to investigation");
      void queryClient.invalidateQueries({ queryKey: ["investigations", "inbox"] });
      void queryClient.invalidateQueries({ queryKey: ["investigations", "detail"] });
      setTarget("");
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.message : "Failed to link finding"),
  });

  return (
    <Can permission="investigation:update">
      <div className="flex items-center justify-end gap-2">
        <div className="w-40">
          <Select value={target} onChange={(e) => setTarget(e.target.value)}>
            <option value="">Pick investigation…</option>
            {investigations.map((inv) => (
              <option key={inv.id} value={inv.id}>
                {inv.title}
              </option>
            ))}
          </Select>
        </div>
        <Button
          variant="outline"
          size="sm"
          disabled={!target || mutation.isPending}
          onClick={() => mutation.mutate()}
        >
          {mutation.isPending ? "Linking…" : "Link"}
        </Button>
      </div>
    </Can>
  );
}

function InboxPanel({ investigations }: { investigations: Investigation[] }) {
  const query = useQuery({
    queryKey: ["investigations", "inbox"],
    queryFn: () => apiFetch<InboxAlert[]>("/api/investigations/inbox"),
  });

  const columns: ColumnDef<InboxAlert, unknown>[] = [
    {
      accessorKey: "title",
      header: "Alert",
      cell: ({ row }) => (
        <span className="font-medium">
          {row.original.title || row.original.source_finding_id}
        </span>
      ),
    },
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
      accessorKey: "severity",
      header: "Severity",
      cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
    },
    {
      accessorKey: "created_at",
      header: "Created",
      cell: ({ row }) => (
        <span className="text-muted-foreground">
          {formatDateTime(row.original.created_at)}
        </span>
      ),
    },
    {
      id: "actions",
      header: "",
      cell: ({ row }) => (
        <LinkInboxAlert alert={row.original} investigations={investigations} />
      ),
    },
  ];

  return (
    <Card>
      <CardHeader>
        <CardTitle>Inbox</CardTitle>
        <CardDescription>
          Unlinked alerts awaiting triage. Open an investigation to link them.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <DataTable
          columns={columns}
          rows={query.data ?? []}
          isLoading={query.isLoading}
          isError={query.isError}
          onRetry={() => void query.refetch()}
          emptyMessage="Inbox is empty — no unlinked alerts."
        />
      </CardContent>
    </Card>
  );
}

export default function InvestigationsPage() {
  const [status, setStatus] = useState("");
  const [priority, setPriority] = useState("");
  const [showForm, setShowForm] = useState(false);

  const query = useQuery({
    queryKey: ["investigations", "list", status, priority],
    queryFn: () => {
      const params = new URLSearchParams({ limit: "50" });
      if (status) params.set("status", status);
      if (priority) params.set("priority", priority);
      return apiFetch<Investigation[]>(`/api/investigations?${params.toString()}`);
    },
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Investigations"
        description="Triage cases and link related findings."
        actions={
          <Can permission="investigation:create">
            <Button onClick={() => setShowForm((v) => !v)}>
              {showForm ? "Close form" : "New Investigation"}
            </Button>
          </Can>
        }
      />

      {showForm ? <NewInvestigationForm onDone={() => setShowForm(false)} /> : null}

      <div className="flex flex-wrap gap-3">
        <div className="w-48">
          <Select value={status} onChange={(e) => setStatus(e.target.value)}>
            {STATUS_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </Select>
        </div>
        <div className="w-48">
          <Select value={priority} onChange={(e) => setPriority(e.target.value)}>
            {PRIORITY_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </Select>
        </div>
      </div>

      <DataTable
        columns={investigationColumns}
        rows={query.data ?? []}
        isLoading={query.isLoading}
        isError={query.isError}
        onRetry={() => void query.refetch()}
        emptyMessage="No investigations match the current filter."
      />

      <InboxPanel investigations={query.data ?? []} />
    </div>
  );
}
