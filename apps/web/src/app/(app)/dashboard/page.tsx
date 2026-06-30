"use client";

import { useQuery } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import { useMemo } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { DataTable } from "@/components/data-table";
import { SeverityBadge } from "@/components/severity-badge";
import { PageHeader } from "@/components/states";
import { StatusBadge } from "@/components/status-badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { apiFetch } from "@/lib/api";
import type { Alert, AlertMetrics, Severity } from "@/lib/types";
import { formatDateTime } from "@/lib/utils";

const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
];

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#dc2626",
  high: "#f97316",
  medium: "#fbbf24",
  low: "#0ea5e9",
  informational: "#94a3b8",
};

const recentAlertColumns: ColumnDef<Alert, unknown>[] = [
  {
    accessorKey: "title",
    header: "Title",
    cell: ({ row }) => (
      <span className="font-medium">{row.original.title || row.original.id}</span>
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

export default function DashboardPage() {
  const metricsQuery = useQuery({
    queryKey: ["alerts", "metrics"],
    queryFn: () => apiFetch<AlertMetrics>("/api/alerts/metrics"),
  });

  const recentQuery = useQuery({
    queryKey: ["alerts", "recent"],
    queryFn: () => apiFetch<Alert[]>("/api/alerts?limit=5"),
  });

  const counts = useMemo(
    () => metricsQuery.data?.open_by_severity ?? {},
    [metricsQuery.data],
  );
  const total = SEVERITY_ORDER.reduce((sum, s) => sum + (counts[s] ?? 0), 0);

  const chartData = useMemo(
    () =>
      SEVERITY_ORDER.map((s) => ({
        severity: s.charAt(0).toUpperCase() + s.slice(1),
        key: s,
        count: counts[s] ?? 0,
      })),
    [counts],
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dashboard"
        description="Open alerts across all monitoring modules."
      />

      {/* Summary cards */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-6">
        <SummaryCard
          label="Total open"
          value={total}
          isLoading={metricsQuery.isLoading}
          isError={metricsQuery.isError}
          accent="text-foreground"
        />
        {SEVERITY_ORDER.map((s) => (
          <SummaryCard
            key={s}
            label={s.charAt(0).toUpperCase() + s.slice(1)}
            value={counts[s] ?? 0}
            isLoading={metricsQuery.isLoading}
            isError={metricsQuery.isError}
            dotColor={SEVERITY_COLOR[s]}
          />
        ))}
      </div>

      {/* Chart */}
      <Card>
        <CardHeader>
          <CardTitle>Open alerts by severity</CardTitle>
          <CardDescription>Live counts from the alert engine.</CardDescription>
        </CardHeader>
        <CardContent>
          {metricsQuery.isLoading ? (
            <Skeleton className="h-[280px] w-full" />
          ) : metricsQuery.isError ? (
            <div className="flex h-[280px] items-center justify-center text-sm text-muted-foreground">
              Unable to load metrics.
            </div>
          ) : (
            <div className="h-[280px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="severity" tickLine={false} axisLine={false} />
                  <YAxis allowDecimals={false} tickLine={false} axisLine={false} />
                  <Tooltip cursor={{ fill: "rgba(148,163,184,0.1)" }} />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {chartData.map((entry) => (
                      <Cell key={entry.key} fill={SEVERITY_COLOR[entry.key]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Recent alerts */}
      <Card>
        <CardHeader>
          <CardTitle>Recent alerts</CardTitle>
          <CardDescription>The five most recent alerts.</CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={recentAlertColumns}
            rows={recentQuery.data ?? []}
            isLoading={recentQuery.isLoading}
            isError={recentQuery.isError}
            onRetry={() => void recentQuery.refetch()}
            emptyMessage="No recent alerts."
          />
        </CardContent>
      </Card>
    </div>
  );
}

function SummaryCard({
  label,
  value,
  isLoading,
  isError,
  dotColor,
  accent,
}: {
  label: string;
  value: number;
  isLoading?: boolean;
  isError?: boolean;
  dotColor?: string;
  accent?: string;
}) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
          {dotColor ? (
            <span
              className="h-2.5 w-2.5 rounded-full"
              style={{ backgroundColor: dotColor }}
            />
          ) : null}
          {label}
        </div>
        {isLoading ? (
          <Skeleton className="mt-2 h-7 w-12" />
        ) : isError ? (
          <p className="mt-2 text-2xl font-semibold text-muted-foreground">—</p>
        ) : (
          <p className={`mt-2 text-2xl font-semibold ${accent ?? ""}`}>{value}</p>
        )}
      </CardContent>
    </Card>
  );
}
