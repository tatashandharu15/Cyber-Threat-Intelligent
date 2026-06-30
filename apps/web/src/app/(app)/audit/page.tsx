"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import { useState } from "react";
import { toast } from "sonner";
import { Can } from "@/components/can";
import { DataTable } from "@/components/data-table";
import { PageHeader } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { apiFetch, ApiError } from "@/lib/api";
import type { AuditEvent, AuditVerifyResult } from "@/lib/types";
import { formatDateTime } from "@/lib/utils";

const OUTCOME_OPTIONS = [
  { value: "", label: "All outcomes" },
  { value: "success", label: "Success" },
  { value: "failure", label: "Failure" },
  { value: "partial", label: "Partial" },
];

function outcomeVariant(outcome: string): "success" | "destructive" | "warning" | "neutral" {
  switch (outcome) {
    case "success":
      return "success";
    case "failure":
      return "destructive";
    case "partial":
      return "warning";
    default:
      return "neutral";
  }
}

function short(value?: string | null): string {
  if (!value) return "—";
  return value.length > 8 ? value.slice(0, 8) : value;
}

function VerifyButton({ id }: { id: string }) {
  const mutation = useMutation({
    mutationFn: () => apiFetch<AuditVerifyResult>(`/api/audit-logs/${id}/verify`),
    onSuccess: (result) => {
      if (result.valid) {
        toast.success(`Event ${short(id)} verified — integrity intact`);
      } else {
        toast.error(`Event ${short(id)} FAILED verification — possible tampering`);
      }
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.message : "Verification failed"),
  });

  return (
    <Can permission="audit:read">
      <Button
        variant="outline"
        size="sm"
        disabled={mutation.isPending}
        onClick={() => mutation.mutate()}
      >
        {mutation.isPending ? "Verifying…" : "Verify"}
      </Button>
    </Can>
  );
}

const columns: ColumnDef<AuditEvent, unknown>[] = [
  {
    accessorKey: "created_at",
    header: "Time",
    cell: ({ row }) => (
      <span className="text-muted-foreground">
        {formatDateTime(row.original.created_at)}
      </span>
    ),
  },
  {
    accessorKey: "actor_id",
    header: "Actor",
    cell: ({ row }) => (
      <span className="font-mono text-xs">{short(row.original.actor_id)}</span>
    ),
  },
  {
    accessorKey: "event_type",
    header: "Event type",
    cell: ({ row }) => <span>{row.original.event_type}</span>,
  },
  {
    accessorKey: "resource_type",
    header: "Resource",
    cell: ({ row }) => (
      <span className="text-muted-foreground">{row.original.resource_type}</span>
    ),
  },
  {
    accessorKey: "resource_id",
    header: "Resource ID",
    cell: ({ row }) => (
      <span className="font-mono text-xs">{short(row.original.resource_id)}</span>
    ),
  },
  {
    accessorKey: "action",
    header: "Action",
    cell: ({ row }) => (
      <span className="text-muted-foreground">{row.original.action}</span>
    ),
  },
  {
    accessorKey: "outcome",
    header: "Outcome",
    cell: ({ row }) => (
      <Badge variant={outcomeVariant(row.original.outcome)}>
        {row.original.outcome}
      </Badge>
    ),
  },
  {
    id: "actions",
    header: "",
    cell: ({ row }) => <VerifyButton id={row.original.id} />,
  },
];

export default function AuditPage() {
  const [eventType, setEventType] = useState("");
  const [resourceType, setResourceType] = useState("");
  const [actorId, setActorId] = useState("");
  const [outcome, setOutcome] = useState("");

  const query = useQuery({
    queryKey: ["audit-logs", "list", eventType, resourceType, actorId, outcome],
    queryFn: () => {
      const params = new URLSearchParams({ limit: "50" });
      if (eventType.trim()) params.set("event_type", eventType.trim());
      if (resourceType.trim()) params.set("resource_type", resourceType.trim());
      if (actorId.trim()) params.set("actor_id", actorId.trim());
      if (outcome) params.set("outcome", outcome);
      return apiFetch<AuditEvent[]>(`/api/audit-logs?${params.toString()}`);
    },
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit"
        description="Tamper-evident audit trail of platform activity."
      />

      <div className="flex flex-wrap gap-3">
        <div className="w-48">
          <Input
            value={eventType}
            onChange={(e) => setEventType(e.target.value)}
            placeholder="Event type…"
          />
        </div>
        <div className="w-48">
          <Input
            value={resourceType}
            onChange={(e) => setResourceType(e.target.value)}
            placeholder="Resource type…"
          />
        </div>
        <div className="w-48">
          <Input
            value={actorId}
            onChange={(e) => setActorId(e.target.value)}
            placeholder="Actor ID…"
          />
        </div>
        <div className="w-44">
          <Select value={outcome} onChange={(e) => setOutcome(e.target.value)}>
            {OUTCOME_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </Select>
        </div>
      </div>

      <DataTable
        columns={columns}
        rows={query.data ?? []}
        isLoading={query.isLoading}
        isError={query.isError}
        onRetry={() => void query.refetch()}
        emptyMessage="No audit events match the current filter."
      />
    </div>
  );
}
