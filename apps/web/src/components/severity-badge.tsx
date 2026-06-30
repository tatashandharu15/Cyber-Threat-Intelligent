import { Badge } from "@/components/ui/badge";
import type { Severity } from "@/lib/types";

const SEVERITY_VARIANT: Record<
  Severity,
  "critical" | "high" | "medium" | "low" | "informational"
> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  informational: "informational",
};

export function SeverityBadge({ severity }: { severity?: string | null }) {
  if (!severity) return <span className="text-muted-foreground">—</span>;
  const key = severity.toLowerCase() as Severity;
  const variant = SEVERITY_VARIANT[key] ?? "neutral";
  return <Badge variant={variant}>{severity.toUpperCase()}</Badge>;
}
