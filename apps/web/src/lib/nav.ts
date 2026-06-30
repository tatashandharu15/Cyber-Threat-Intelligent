import {
  Bell,
  FileSearch,
  LayoutDashboard,
  ScrollText,
  Search,
  ServerCog,
  ShieldAlert,
  Target,
  type LucideIcon,
} from "lucide-react";

export interface NavItem {
  label: string;
  href: string;
  icon: LucideIcon;
  /** Permission required to see this item. Undefined = always visible. */
  permission?: string;
}

export const NAV_ITEMS: NavItem[] = [
  { label: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
  { label: "Findings", href: "/findings", icon: FileSearch, permission: "finding:read" },
  {
    label: "Investigation",
    href: "/investigations",
    icon: Search,
    permission: "investigation:read",
  },
  { label: "Indicators", href: "/indicators", icon: Target, permission: "indicator:read" },
  { label: "Takedowns", href: "/takedowns", icon: ShieldAlert, permission: "takedown:read" },
  {
    label: "Notifications",
    href: "/notifications",
    icon: Bell,
    permission: "notification:read",
  },
  { label: "Audit", href: "/audit", icon: ScrollText, permission: "audit:read" },
  { label: "Assets", href: "/assets", icon: ServerCog, permission: "asset:read" },
];
