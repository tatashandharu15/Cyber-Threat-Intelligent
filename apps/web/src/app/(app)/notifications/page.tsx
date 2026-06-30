"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import { useState } from "react";
import { toast } from "sonner";
import { Can } from "@/components/can";
import { DataTable } from "@/components/data-table";
import { SeverityBadge } from "@/components/severity-badge";
import { PageHeader } from "@/components/states";
import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/select";
import { apiFetch, ApiError } from "@/lib/api";
import type { Notification } from "@/lib/types";
import { formatDateTime } from "@/lib/utils";

const STATUS_OPTIONS = [
  { value: "", label: "All statuses" },
  { value: "pending", label: "Pending" },
  { value: "sent", label: "Sent" },
  { value: "suppressed", label: "Suppressed" },
];

const CHANNEL_OPTIONS = [
  { value: "", label: "All channels" },
  { value: "in_app", label: "In-app" },
  { value: "email", label: "Email" },
  { value: "slack", label: "Slack" },
  { value: "teams", label: "Teams" },
  { value: "webhook", label: "Webhook" },
];

function MarkReadButton({ notification }: { notification: Notification }) {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: () =>
      apiFetch(`/api/notifications/${notification.id}/read`, { method: "POST" }),
    onSuccess: () => {
      toast.success("Marked as read");
      void queryClient.invalidateQueries({ queryKey: ["notifications"] });
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.message : "Failed to mark read"),
  });

  if (notification.read_at) {
    return <span className="text-xs text-muted-foreground">Read</span>;
  }

  return (
    <Can permission="notification:update">
      <Button
        variant="outline"
        size="sm"
        disabled={mutation.isPending}
        onClick={() => mutation.mutate()}
      >
        {mutation.isPending ? "…" : "Mark read"}
      </Button>
    </Can>
  );
}

const columns: ColumnDef<Notification, unknown>[] = [
  {
    accessorKey: "subject",
    header: "Subject",
    cell: ({ row }) => {
      const unread = !row.original.read_at;
      return (
        <div className="flex items-center gap-2">
          {unread ? (
            <span
              className="h-2 w-2 shrink-0 rounded-full bg-primary"
              aria-label="Unread"
            />
          ) : null}
          <span className={unread ? "font-semibold" : "font-normal"}>
            {row.original.subject || row.original.event_type}
          </span>
        </div>
      );
    },
  },
  {
    accessorKey: "event_type",
    header: "Event",
    cell: ({ row }) => (
      <span className="text-muted-foreground">{row.original.event_type}</span>
    ),
  },
  {
    accessorKey: "channel",
    header: "Channel",
    cell: ({ row }) => <Badge variant="neutral">{row.original.channel}</Badge>,
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
  {
    id: "actions",
    header: "",
    cell: ({ row }) => <MarkReadButton notification={row.original} />,
  },
];

export default function NotificationsPage() {
  const [status, setStatus] = useState("");
  const [channel, setChannel] = useState("");

  const query = useQuery({
    queryKey: ["notifications", "list", status, channel],
    queryFn: () => {
      const params = new URLSearchParams({ limit: "50" });
      if (status) params.set("status", status);
      if (channel) params.set("channel", channel);
      return apiFetch<Notification[]>(`/api/notifications?${params.toString()}`);
    },
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Notifications"
        description="Delivery log across all notification channels."
      />

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
          <Select value={channel} onChange={(e) => setChannel(e.target.value)}>
            {CHANNEL_OPTIONS.map((opt) => (
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
        emptyMessage="No notifications match the current filter."
      />
    </div>
  );
}
