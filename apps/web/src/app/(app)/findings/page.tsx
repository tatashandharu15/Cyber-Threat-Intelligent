"use client";

import { useQuery } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import { useState } from "react";
import { DataTable } from "@/components/data-table";
import { SeverityBadge } from "@/components/severity-badge";
import { PageHeader } from "@/components/states";
import { StatusBadge } from "@/components/status-badge";
import { Select } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { apiFetch } from "@/lib/api";
import type { Finding, FindingModule } from "@/lib/types";
import { formatDateTime } from "@/lib/utils";

const MODULES: { value: FindingModule; label: string }[] = [
  { value: "dlm", label: "DLM" },
  { value: "clm", label: "CLM" },
  { value: "dwm", label: "DWM" },
  { value: "brm", label: "BRM" },
  { value: "phm", label: "PHM" },
];

const STATUS_OPTIONS = [
  { value: "", label: "All statuses" },
  { value: "open", label: "Open" },
  { value: "in_progress", label: "In progress" },
  { value: "resolved", label: "Resolved" },
  { value: "closed", label: "Closed" },
  { value: "false_positive", label: "False positive" },
  { value: "accepted_risk", label: "Accepted risk" },
];

function identifierFor(f: Finding): string {
  if (f.title) return f.title;
  // CLM findings have no title — fall back to masked indicator / credential type.
  if (f.masked_indicator || f.credential_type) {
    return [f.masked_indicator, f.credential_type].filter(Boolean).join(" · ");
  }
  return f.id;
}

const columns: ColumnDef<Finding, unknown>[] = [
  {
    id: "identifier",
    header: "Title / Identifier",
    cell: ({ row }) => (
      <span className="font-medium">{identifierFor(row.original)}</span>
    ),
  },
  {
    accessorKey: "finding_type",
    header: "Type",
    cell: ({ row }) => (
      <span className="text-muted-foreground">{row.original.finding_type ?? "—"}</span>
    ),
  },
  {
    accessorKey: "severity",
    header: "Severity",
    cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
  },
  {
    accessorKey: "status",
    header: "Status",
    cell: ({ row }) => <StatusBadge status={row.original.status} />,
  },
  {
    accessorKey: "confidence_score",
    header: "Confidence",
    cell: ({ row }) => {
      const score = row.original.confidence_score;
      return (
        <span className="text-muted-foreground">
          {typeof score === "number" ? `${Math.round(score * 100) / 100}` : "—"}
        </span>
      );
    },
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

function ModuleFindings({ module }: { module: FindingModule }) {
  const [status, setStatus] = useState("");

  const query = useQuery({
    queryKey: ["findings", module, status],
    queryFn: () => {
      const params = new URLSearchParams({ limit: "50" });
      if (status) params.set("status", status);
      return apiFetch<Finding[]>(`/api/${module}/findings?${params.toString()}`);
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-end">
        <div className="w-48">
          <Select value={status} onChange={(e) => setStatus(e.target.value)}>
            {STATUS_OPTIONS.map((opt) => (
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
        emptyMessage={`No ${module.toUpperCase()} findings match the current filter.`}
      />
    </div>
  );
}

export default function FindingsPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Findings"
        description="Findings emitted by each monitoring module."
      />
      <Tabs defaultValue="dlm">
        <TabsList>
          {MODULES.map((m) => (
            <TabsTrigger key={m.value} value={m.value}>
              {m.label}
            </TabsTrigger>
          ))}
        </TabsList>
        {MODULES.map((m) => (
          <TabsContent key={m.value} value={m.value}>
            <ModuleFindings module={m.value} />
          </TabsContent>
        ))}
      </Tabs>
    </div>
  );
}
