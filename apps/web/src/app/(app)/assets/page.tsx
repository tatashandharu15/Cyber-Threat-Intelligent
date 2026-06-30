"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import { useState } from "react";
import { toast } from "sonner";
import { Can } from "@/components/can";
import { DataTable } from "@/components/data-table";
import { PageHeader } from "@/components/states";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/select";
import { apiFetch, ApiError } from "@/lib/api";
import type { Asset } from "@/lib/types";
import { formatDateTime } from "@/lib/utils";

const ASSET_TYPE_OPTIONS = [
  { value: "", label: "All types" },
  { value: "domain", label: "Domain" },
  { value: "ip_address", label: "IP address" },
  { value: "ip_range", label: "IP range" },
  { value: "email_address", label: "Email address" },
  { value: "email_domain", label: "Email domain" },
  { value: "brand_keyword", label: "Brand keyword" },
  { value: "executive_profile", label: "Executive profile" },
  { value: "mobile_app", label: "Mobile app" },
  { value: "social_handle", label: "Social handle" },
];

const STATUS_OPTIONS = [
  { value: "", label: "All statuses" },
  { value: "active", label: "Active" },
  { value: "paused", label: "Paused" },
  { value: "decommissioned", label: "Decommissioned" },
  { value: "pending_approval", label: "Pending approval" },
];

const CRITICALITY_OPTIONS = [
  { value: "", label: "All criticalities" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

function ApprovalBadge({ status }: { status: string }) {
  if (status === "approved") {
    return <Badge variant="success">Approved</Badge>;
  }
  if (status === "pending") {
    return <Badge variant="warning">Pending</Badge>;
  }
  return <Badge variant="neutral">{status}</Badge>;
}

function ApproveButton({ asset }: { asset: Asset }) {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: () =>
      apiFetch<Asset>(`/api/assets/${asset.id}/approve`, { method: "POST" }),
    onSuccess: () => {
      toast.success("Asset approved");
      void queryClient.invalidateQueries({ queryKey: ["assets"] });
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.message : "Failed to approve asset"),
  });

  if (asset.approval_status !== "pending") {
    return null;
  }

  return (
    <Can permission="asset:approve">
      <Button
        variant="outline"
        size="sm"
        disabled={mutation.isPending}
        onClick={() => mutation.mutate()}
      >
        {mutation.isPending ? "Approving…" : "Approve"}
      </Button>
    </Can>
  );
}

const columns: ColumnDef<Asset, unknown>[] = [
  {
    accessorKey: "value",
    header: "Value",
    cell: ({ row }) => (
      <span className="font-medium break-all">{row.original.value}</span>
    ),
  },
  {
    accessorKey: "display_name",
    header: "Name",
    cell: ({ row }) => (
      <span className="text-muted-foreground">
        {row.original.display_name || "—"}
      </span>
    ),
  },
  {
    accessorKey: "asset_type",
    header: "Type",
    cell: ({ row }) => (
      <span className="text-muted-foreground">
        {row.original.asset_type.replace(/_/g, " ")}
      </span>
    ),
  },
  {
    accessorKey: "criticality",
    header: "Criticality",
    cell: ({ row }) => <SeverityBadge severity={row.original.criticality} />,
  },
  {
    accessorKey: "status",
    header: "Status",
    cell: ({ row }) => <StatusBadge status={row.original.status} />,
  },
  {
    accessorKey: "approval_status",
    header: "Approval",
    cell: ({ row }) => <ApprovalBadge status={row.original.approval_status} />,
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
    cell: ({ row }) => <ApproveButton asset={row.original} />,
  },
];

export default function AssetsPage() {
  const [assetType, setAssetType] = useState("");
  const [status, setStatus] = useState("");
  const [criticality, setCriticality] = useState("");

  const query = useQuery({
    queryKey: ["assets", "list", assetType, status, criticality],
    queryFn: () => {
      const params = new URLSearchParams({ limit: "50" });
      if (assetType) params.set("asset_type", assetType);
      if (status) params.set("status", status);
      if (criticality) params.set("criticality", criticality);
      return apiFetch<Asset[]>(`/api/assets?${params.toString()}`);
    },
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Assets"
        description="Monitored assets and their approval state."
      />

      <div className="flex flex-wrap gap-3">
        <div className="w-48">
          <Select value={assetType} onChange={(e) => setAssetType(e.target.value)}>
            {ASSET_TYPE_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </Select>
        </div>
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
          <Select
            value={criticality}
            onChange={(e) => setCriticality(e.target.value)}
          >
            {CRITICALITY_OPTIONS.map((opt) => (
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
        emptyMessage="No assets match the current filter."
      />
    </div>
  );
}
