import { Skeleton } from "@/components/ui/skeleton";

export default function AssetsLoading() {
  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <Skeleton className="h-8 w-36" />
        <Skeleton className="h-4 w-72" />
      </div>
      <div className="flex gap-3">
        <Skeleton className="h-9 w-48" />
        <Skeleton className="h-9 w-48" />
        <Skeleton className="h-9 w-48" />
      </div>
      <Skeleton className="h-64 w-full rounded-lg" />
    </div>
  );
}
