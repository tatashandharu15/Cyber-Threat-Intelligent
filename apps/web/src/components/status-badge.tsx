import { Badge, type BadgeProps } from "@/components/ui/badge";

const STATUS_VARIANT: Record<string, BadgeProps["variant"]> = {
  open: "warning",
  acknowledged: "secondary",
  in_progress: "default",
  resolved: "success",
  closed: "neutral",
  suppressed: "neutral",
  false_positive: "neutral",
  accepted_risk: "secondary",
};

function humanize(value: string): string {
  return value
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

export function StatusBadge({ status }: { status?: string | null }) {
  if (!status) return <span className="text-muted-foreground">—</span>;
  const variant = STATUS_VARIANT[status.toLowerCase()] ?? "neutral";
  return <Badge variant={variant}>{humanize(status)}</Badge>;
}
