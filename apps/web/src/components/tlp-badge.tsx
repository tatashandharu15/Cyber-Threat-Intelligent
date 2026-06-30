import { cn } from "@/lib/utils";

const TLP_STYLES: Record<string, string> = {
  red: "bg-red-600 text-white",
  amber: "bg-amber-400 text-black",
  green: "bg-emerald-500 text-black",
  white: "bg-white text-black border border-slate-300",
};

export function TlpBadge({ tlp }: { tlp?: string | null }) {
  if (!tlp) return <span className="text-muted-foreground">—</span>;
  const key = tlp.toLowerCase().replace("tlp:", "").trim();
  const style = TLP_STYLES[key] ?? "bg-slate-400 text-white";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide",
        style,
      )}
    >
      TLP:{key}
    </span>
  );
}
