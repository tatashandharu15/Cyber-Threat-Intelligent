import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary text-primary-foreground",
        secondary: "border-transparent bg-secondary text-secondary-foreground",
        destructive: "border-transparent bg-destructive text-destructive-foreground",
        outline: "text-foreground",
        // Severity palette
        critical: "border-transparent bg-red-600 text-white",
        high: "border-transparent bg-orange-500 text-white",
        medium: "border-transparent bg-amber-400 text-amber-950",
        low: "border-transparent bg-sky-500 text-white",
        informational: "border-transparent bg-slate-400 text-white",
        // Generic status palette
        success: "border-transparent bg-emerald-600 text-white",
        warning: "border-transparent bg-amber-500 text-amber-950",
        neutral: "border-transparent bg-slate-200 text-slate-800",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { Badge, badgeVariants };
