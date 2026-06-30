"use client";

import { ChevronDown, LogOut, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useAuth } from "@/lib/auth";
import { NAV_ITEMS } from "@/lib/nav";
import { cn } from "@/lib/utils";

function initials(value: string): string {
  const parts = value.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "?";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

function Sidebar() {
  const pathname = usePathname();
  const { hasPermission } = useAuth();
  const items = NAV_ITEMS.filter((item) => hasPermission(item.permission));

  return (
    <aside className="hidden w-64 shrink-0 flex-col border-r bg-card md:flex">
      <div className="flex h-14 items-center gap-2 border-b px-5">
        <ShieldCheck className="h-6 w-6 text-primary" />
        <span className="text-sm font-semibold tracking-tight">SiberIndo CTI</span>
      </div>
      <nav className="flex-1 space-y-1 overflow-y-auto p-3">
        {items.map((item) => {
          const Icon = item.icon;
          const active =
            pathname === item.href || pathname.startsWith(`${item.href}/`);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                active
                  ? "bg-accent text-accent-foreground"
                  : "text-muted-foreground hover:bg-accent/50 hover:text-foreground",
              )}
            >
              <Icon className="h-4 w-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}

function TopBar() {
  const { me, logout } = useAuth();
  const displayName = me?.roles?.[0]
    ? me.roles.join(", ")
    : me?.user_id ?? "Account";
  const tenant = me?.tenant_id ?? "—";

  return (
    <header className="flex h-14 items-center justify-between gap-4 border-b bg-background px-4 md:px-6">
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <span className="font-medium text-foreground md:hidden">SiberIndo CTI</span>
        <span className="hidden md:inline">Tenant</span>
        <code className="rounded bg-muted px-1.5 py-0.5 text-xs">{tenant}</code>
      </div>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" className="h-9 gap-2 px-2">
            <Avatar className="h-7 w-7">
              <AvatarFallback>{initials(displayName)}</AvatarFallback>
            </Avatar>
            <span className="hidden max-w-[160px] truncate text-sm md:inline">
              {displayName}
            </span>
            <ChevronDown className="h-4 w-4 text-muted-foreground" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56">
          <DropdownMenuLabel>
            <div className="space-y-0.5">
              <p className="truncate text-sm font-medium">{displayName}</p>
              <p className="truncate text-xs text-muted-foreground">
                {me?.session_id ? `Session ${me.session_id.slice(0, 8)}` : "Signed in"}
              </p>
            </div>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={() => void logout()}>
            <LogOut className="h-4 w-4" />
            Log out
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </header>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen bg-background">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar />
        <main className="flex-1 space-y-6 p-4 md:p-6 lg:p-8">{children}</main>
      </div>
    </div>
  );
}
