"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import { Can } from "@/components/can";
import { DataTable } from "@/components/data-table";
import { PageHeader } from "@/components/states";
import { TlpBadge } from "@/components/tlp-badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { apiFetch, ApiError } from "@/lib/api";
import type { Indicator, IndicatorType, TlpMarking } from "@/lib/types";
import { formatDateTime } from "@/lib/utils";

const INDICATOR_TYPES: { value: IndicatorType; label: string }[] = [
  { value: "domain", label: "Domain" },
  { value: "ip_address", label: "IP address" },
  { value: "url_defanged", label: "URL (defanged)" },
  { value: "hash_md5", label: "Hash (MD5)" },
  { value: "hash_sha1", label: "Hash (SHA1)" },
  { value: "hash_sha256", label: "Hash (SHA256)" },
  { value: "email_address", label: "Email address" },
  { value: "asn", label: "ASN" },
  { value: "certificate_fingerprint", label: "Certificate fingerprint" },
  { value: "mutex", label: "Mutex" },
  { value: "registry_key", label: "Registry key" },
  { value: "file_path", label: "File path" },
];

const TLP_MARKINGS: { value: TlpMarking; label: string }[] = [
  { value: "TLP:WHITE", label: "TLP:WHITE" },
  { value: "TLP:GREEN", label: "TLP:GREEN" },
  { value: "TLP:AMBER", label: "TLP:AMBER" },
  { value: "TLP:RED", label: "TLP:RED" },
];

function AddIndicatorForm({ onDone }: { onDone: () => void }) {
  const queryClient = useQueryClient();
  const [indicatorType, setIndicatorType] = useState<IndicatorType>("domain");
  const [value, setValue] = useState("");
  const [tlpMarking, setTlpMarking] = useState<TlpMarking>("TLP:AMBER");
  const [confidence, setConfidence] = useState("");
  const [sourceModule, setSourceModule] = useState("");
  const [tags, setTags] = useState("");

  const mutation = useMutation({
    mutationFn: () => {
      const conf = confidence.trim() ? Number(confidence) : null;
      const tagList = tags
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);
      return apiFetch<Indicator>("/api/indicators", {
        method: "POST",
        body: JSON.stringify({
          indicator_type: indicatorType,
          value: value.trim(),
          tlp_marking: tlpMarking,
          confidence: conf,
          source_module: sourceModule.trim() || null,
          tags: tagList,
        }),
      });
    },
    onSuccess: () => {
      toast.success("Indicator added");
      void queryClient.invalidateQueries({ queryKey: ["indicators"] });
      onDone();
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.message : "Failed to add indicator"),
  });

  function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!value.trim()) {
      toast.error("Value is required");
      return;
    }
    if (confidence.trim()) {
      const n = Number(confidence);
      if (Number.isNaN(n)) {
        toast.error("Confidence must be a number");
        return;
      }
    }
    mutation.mutate();
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Add indicator</CardTitle>
        <CardDescription>Record a new threat indicator (IOC).</CardDescription>
      </CardHeader>
      <CardContent>
        <form className="grid gap-4 md:grid-cols-2" onSubmit={onSubmit}>
          <div className="space-y-2">
            <Label htmlFor="ind-type">Type</Label>
            <Select
              id="ind-type"
              value={indicatorType}
              onChange={(e) => setIndicatorType(e.target.value as IndicatorType)}
            >
              {INDICATOR_TYPES.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </Select>
          </div>
          <div className="space-y-2">
            <Label htmlFor="ind-value">Value</Label>
            <Input
              id="ind-value"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="evil.example.com"
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="ind-tlp">TLP marking</Label>
            <Select
              id="ind-tlp"
              value={tlpMarking}
              onChange={(e) => setTlpMarking(e.target.value as TlpMarking)}
            >
              {TLP_MARKINGS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </Select>
          </div>
          <div className="space-y-2">
            <Label htmlFor="ind-confidence">Confidence (optional)</Label>
            <Input
              id="ind-confidence"
              value={confidence}
              onChange={(e) => setConfidence(e.target.value)}
              placeholder="0.0 – 1.0"
              inputMode="decimal"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="ind-source">Source module (optional)</Label>
            <Input
              id="ind-source"
              value={sourceModule}
              onChange={(e) => setSourceModule(e.target.value)}
              placeholder="dlm, brm, …"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="ind-tags">Tags (comma-separated, optional)</Label>
            <Input
              id="ind-tags"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="phishing, campaign-x"
            />
          </div>
          <div className="flex gap-2 md:col-span-2">
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? "Adding…" : "Add indicator"}
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

function RowActions({ indicator }: { indicator: Indicator }) {
  const queryClient = useQueryClient();

  const editTlp = useMutation({
    mutationFn: (tlp_marking: TlpMarking) =>
      apiFetch<Indicator>(`/api/indicators/${indicator.id}`, {
        method: "PATCH",
        body: JSON.stringify({ tlp_marking }),
      }),
    onSuccess: () => {
      toast.success("TLP marking updated");
      void queryClient.invalidateQueries({ queryKey: ["indicators"] });
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.message : "Failed to update TLP"),
  });

  const remove = useMutation({
    mutationFn: () =>
      apiFetch(`/api/indicators/${indicator.id}`, { method: "DELETE" }),
    onSuccess: () => {
      toast.success("Indicator deleted");
      void queryClient.invalidateQueries({ queryKey: ["indicators"] });
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.message : "Failed to delete indicator"),
  });

  return (
    <Can permission="indicator:update">
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="sm">
            Actions
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuLabel>Set TLP marking</DropdownMenuLabel>
          {TLP_MARKINGS.map((opt) => (
            <DropdownMenuItem
              key={opt.value}
              disabled={editTlp.isPending || indicator.tlp_marking === opt.value}
              onSelect={() => editTlp.mutate(opt.value)}
            >
              {opt.label}
            </DropdownMenuItem>
          ))}
          <DropdownMenuSeparator />
          <DropdownMenuItem
            className="text-destructive focus:text-destructive"
            disabled={remove.isPending}
            onSelect={() => {
              if (
                window.confirm(`Delete indicator "${indicator.value}"? This cannot be undone.`)
              ) {
                remove.mutate();
              }
            }}
          >
            Delete
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </Can>
  );
}

const columns: ColumnDef<Indicator, unknown>[] = [
  {
    accessorKey: "value",
    header: "Value",
    cell: ({ row }) => (
      <span className="font-mono text-xs break-all">{row.original.value}</span>
    ),
  },
  {
    accessorKey: "indicator_type",
    header: "Type",
    cell: ({ row }) => (
      <span className="text-muted-foreground">{row.original.indicator_type}</span>
    ),
  },
  {
    accessorKey: "tlp_marking",
    header: "TLP",
    cell: ({ row }) => <TlpBadge tlp={row.original.tlp_marking} />,
  },
  {
    accessorKey: "confidence",
    header: "Confidence",
    cell: ({ row }) => (
      <span className="text-muted-foreground">
        {typeof row.original.confidence === "number"
          ? row.original.confidence
          : "—"}
      </span>
    ),
  },
  {
    accessorKey: "source_module",
    header: "Source",
    cell: ({ row }) => (
      <span className="uppercase text-muted-foreground">
        {row.original.source_module || "—"}
      </span>
    ),
  },
  {
    accessorKey: "last_seen_at",
    header: "Last seen",
    cell: ({ row }) => (
      <span className="text-muted-foreground">
        {formatDateTime(row.original.last_seen_at)}
      </span>
    ),
  },
  {
    id: "actions",
    header: "",
    cell: ({ row }) => <RowActions indicator={row.original} />,
  },
];

export default function IndicatorsPage() {
  const [indicatorType, setIndicatorType] = useState("");
  const [tlpMarking, setTlpMarking] = useState("");
  const [value, setValue] = useState("");
  const [showForm, setShowForm] = useState(false);

  const query = useQuery({
    queryKey: ["indicators", "list", indicatorType, tlpMarking, value],
    queryFn: () => {
      const params = new URLSearchParams({ limit: "50" });
      if (indicatorType) params.set("indicator_type", indicatorType);
      if (tlpMarking) params.set("tlp_marking", tlpMarking);
      if (value.trim()) params.set("value", value.trim());
      return apiFetch<Indicator[]>(`/api/indicators?${params.toString()}`);
    },
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Indicators"
        description="Threat indicators (IOCs) shared across the platform."
        actions={
          <Can permission="indicator:create">
            <Button onClick={() => setShowForm((v) => !v)}>
              {showForm ? "Close form" : "Add Indicator"}
            </Button>
          </Can>
        }
      />

      {showForm ? <AddIndicatorForm onDone={() => setShowForm(false)} /> : null}

      <div className="flex flex-wrap gap-3">
        <div className="w-52">
          <Select
            value={indicatorType}
            onChange={(e) => setIndicatorType(e.target.value)}
          >
            <option value="">All types</option>
            {INDICATOR_TYPES.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </Select>
        </div>
        <div className="w-48">
          <Select value={tlpMarking} onChange={(e) => setTlpMarking(e.target.value)}>
            <option value="">All TLP</option>
            {TLP_MARKINGS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </Select>
        </div>
        <div className="w-64">
          <Input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="Search by value…"
          />
        </div>
      </div>

      <DataTable
        columns={columns}
        rows={query.data ?? []}
        isLoading={query.isLoading}
        isError={query.isError}
        onRetry={() => void query.refetch()}
        emptyMessage="No indicators match the current filter."
      />
    </div>
  );
}
