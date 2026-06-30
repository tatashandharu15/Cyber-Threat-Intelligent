import { AlertTriangle, Inbox } from "lucide-react";
import type { ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { TBody, TD, TR } from "@/components/ui/table";
import { cn } from "@/lib/utils";

export function PageHeader({
  title,
  description,
  actions,
  className,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-wrap items-start justify-between gap-4", className)}>
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {description ? (
          <p className="text-sm text-muted-foreground">{description}</p>
        ) : null}
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function ErrorState({
  title = "Something went wrong",
  message = "We couldn't load this data. Please try again.",
  onRetry,
}: {
  title?: string;
  message?: string;
  onRetry?: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed p-10 text-center">
      <AlertTriangle className="h-8 w-8 text-destructive" />
      <div className="space-y-1">
        <p className="font-medium">{title}</p>
        <p className="text-sm text-muted-foreground">{message}</p>
      </div>
      {onRetry ? (
        <Button variant="outline" size="sm" onClick={onRetry}>
          Retry
        </Button>
      ) : null}
    </div>
  );
}

export function EmptyState({
  title = "Nothing here yet",
  message = "There is no data to display.",
  icon,
}: {
  title?: string;
  message?: string;
  icon?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed p-10 text-center">
      {icon ?? <Inbox className="h-8 w-8 text-muted-foreground" />}
      <div className="space-y-1">
        <p className="font-medium">{title}</p>
        <p className="text-sm text-muted-foreground">{message}</p>
      </div>
    </div>
  );
}

export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-3 p-10 text-sm text-muted-foreground">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-muted-foreground border-t-transparent" />
      {label}
    </div>
  );
}

export function DataTableSkeleton({
  columns,
  rows = 6,
}: {
  columns: number;
  rows?: number;
}) {
  return (
    <TBody>
      {Array.from({ length: rows }).map((_, r) => (
        <TR key={r}>
          {Array.from({ length: columns }).map((__, c) => (
            <TD key={c}>
              <Skeleton className="h-4 w-full max-w-[160px]" />
            </TD>
          ))}
        </TR>
      ))}
    </TBody>
  );
}
