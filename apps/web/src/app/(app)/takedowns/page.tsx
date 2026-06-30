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
  SubmissionTargetType,
  Takedown,
  TakedownSourceModule,
} from "@/lib/types";
import { formatDateTime } from "@/lib/utils";

const STATUS_OPTIONS = [
  { value: "", label: "All statuses" },
  { value: "draft", label: "Draft" },
  { value: "submitted", label: "Submitted" },
  { value: "acknowledged", label: "Acknowledged" },
  { value: "actioned", label: "Actioned" },
  { value: "rejected", label: "Rejected" },
  { value: "closed", label: "Closed" },
];

const SOURCE_MODULES: { value: TakedownSourceModule; label: string }[] = [
  { value: "brm", label: "BRM" },
  { value: "phm", label: "PHM" },
];

const TARGET_TYPES: { value: SubmissionTargetType; label: string }[] = [
  { value: "registrar", label: "Registrar" },
  { value: "app_store_operator", label: "App store operator" },
  { value: "social_platform", label: "Social platform" },
  { value: "hosting_provider", label: "Hosting provider" },
  { value: "cert_authority", label: "Certificate authority" },
];

const columns: ColumnDef<Takedown, unknown>[] = [
  {
    accessorKey: "id",
    header: "ID",
    cell: ({ row }) => (
      <Link
        href={`/takedowns/${row.original.id}`}
        className="font-mono text-xs text-primary hover:underline"
      >
        {row.original.id.slice(0, 8)}
      </Link>
    ),
  },
  {
    accessorKey: "source_module",
    header: "Source",
    cell: ({ row }) => (
      <span className="uppercase text-muted-foreground">
        {row.original.source_module}
      </span>
    ),
  },
  {
    accessorKey: "submission_target",
    header: "Target",
    cell: ({ row }) => (
      <span className="break-all">{row.original.submission_target}</span>
    ),
  },
  {
    accessorKey: "submission_target_type",
    header: "Target type",
    cell: ({ row }) => (
      <span className="text-muted-foreground">
        {row.original.submission_target_type.replace(/_/g, " ")}
      </span>
    ),
  },
  {
    accessorKey: "status",
    header: "Status",
    cell: ({ row }) => <StatusBadge status={row.original.status} />,
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

function NewTakedownForm({ onDone }: { onDone: () => void }) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const [sourceModule, setSourceModule] = useState<TakedownSourceModule>("brm");
  const [sourceFindingId, setSourceFindingId] = useState("");
  const [submissionTarget, setSubmissionTarget] = useState("");
  const [targetType, setTargetType] =
    useState<SubmissionTargetType>("registrar");
  const [evidenceRef, setEvidenceRef] = useState("");

  const mutation = useMutation({
    mutationFn: () =>
      apiFetch<Takedown>("/api/takedowns", {
        method: "POST",
        body: JSON.stringify({
          source_module: sourceModule,
          source_finding_id: sourceFindingId.trim(),
          submission_target: submissionTarget.trim(),
          submission_target_type: targetType,
          evidence_package_ref: evidenceRef.trim(),
        }),
      }),
    onSuccess: (created) => {
      toast.success("Takedown created");
      void queryClient.invalidateQueries({ queryKey: ["takedowns"] });
      onDone();
      router.push(`/takedowns/${created.id}`);
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.message : "Failed to create takedown"),
  });

  function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!sourceFindingId.trim() || !submissionTarget.trim() || !evidenceRef.trim()) {
      toast.error("Finding ID, target and evidence reference are required");
      return;
    }
    mutation.mutate();
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>New takedown</CardTitle>
        <CardDescription>Draft a takedown request for an abusive asset.</CardDescription>
      </CardHeader>
      <CardContent>
        <form className="grid gap-4 md:grid-cols-2" onSubmit={onSubmit}>
          <div className="space-y-2">
            <Label htmlFor="td-module">Source module</Label>
            <Select
              id="td-module"
              value={sourceModule}
              onChange={(e) => setSourceModule(e.target.value as TakedownSourceModule)}
            >
              {SOURCE_MODULES.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </Select>
          </div>
          <div className="space-y-2">
            <Label htmlFor="td-finding">Source finding ID</Label>
            <Input
              id="td-finding"
              value={sourceFindingId}
              onChange={(e) => setSourceFindingId(e.target.value)}
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="td-target">Submission target</Label>
            <Input
              id="td-target"
              value={submissionTarget}
              onChange={(e) => setSubmissionTarget(e.target.value)}
              placeholder="abuse@registrar.com"
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="td-target-type">Target type</Label>
            <Select
              id="td-target-type"
              value={targetType}
              onChange={(e) => setTargetType(e.target.value as SubmissionTargetType)}
            >
              {TARGET_TYPES.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </Select>
          </div>
          <div className="space-y-2 md:col-span-2">
            <Label htmlFor="td-evidence">Evidence package reference</Label>
            <Input
              id="td-evidence"
              value={evidenceRef}
              onChange={(e) => setEvidenceRef(e.target.value)}
              placeholder="s3://evidence/case-123.zip"
              required
            />
          </div>
          <div className="flex gap-2 md:col-span-2">
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? "Creating…" : "Create takedown"}
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

export default function TakedownsPage() {
  const [status, setStatus] = useState("");
  const [sourceModule, setSourceModule] = useState("");
  const [showForm, setShowForm] = useState(false);

  const query = useQuery({
    queryKey: ["takedowns", "list", status, sourceModule],
    queryFn: () => {
      const params = new URLSearchParams({ limit: "50" });
      if (status) params.set("status", status);
      if (sourceModule) params.set("source_module", sourceModule);
      return apiFetch<Takedown[]>(`/api/takedowns?${params.toString()}`);
    },
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Takedowns"
        description="Track abuse takedown requests and their lifecycle."
        actions={
          <Can permission="takedown:create">
            <Button onClick={() => setShowForm((v) => !v)}>
              {showForm ? "Close form" : "New Takedown"}
            </Button>
          </Can>
        }
      />

      {showForm ? <NewTakedownForm onDone={() => setShowForm(false)} /> : null}

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
          <Select
            value={sourceModule}
            onChange={(e) => setSourceModule(e.target.value)}
          >
            <option value="">All modules</option>
            {SOURCE_MODULES.map((opt) => (
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
        emptyMessage="No takedowns match the current filter."
      />
    </div>
  );
}
