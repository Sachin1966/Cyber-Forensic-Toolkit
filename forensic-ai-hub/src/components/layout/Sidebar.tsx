import { NavLink, useLocation } from "react-router-dom";
import { cn } from "@/lib/utils";
import {
  LayoutDashboard,
  Globe,
  Mail,
  FileCode,
  Network,
  FileText,
  Cpu,
  Activity,
  Shield,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { useState } from "react";

const navItems = [
  { path: "/", icon: LayoutDashboard, label: "Dashboard" },
  { path: "/url-analyzer", icon: Globe, label: "URL Analyzer" },
  { path: "/email-analyzer", icon: Mail, label: "Email Analyzer" },
  { path: "/file-analyzer", icon: FileCode, label: "File Analyzer" },
  { path: "/pcap-analyzer", icon: Network, label: "PCAP Analyzer" },
  { path: "/reports", icon: FileText, label: "Reports" },
  { path: "/training", icon: Cpu, label: "Training" },
  { path: "/mlops", icon: Activity, label: "MLOps" },
];

export function Sidebar() {
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(false);

  return (
    <aside
      className={cn(
        "fixed left-0 top-0 h-screen bg-sidebar border-r border-sidebar-border z-50 transition-all duration-300 flex flex-col",
        collapsed ? "w-20" : "w-64"
      )}
    >
      {/* Logo */}
      <div className="p-4 border-b border-sidebar-border">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-primary to-secondary flex items-center justify-center cyber-glow">
            <Shield className="w-6 h-6 text-primary-foreground" />
          </div>
          {!collapsed && (
            <div className="flex flex-col">
              <span className="font-display font-bold text-primary text-sm tracking-wider">
                CYBER FORENSIC
              </span>
              <span className="text-xs text-muted-foreground">AI Toolkit</span>
            </div>
          )}
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4 space-y-2 overflow-y-auto">
        {navItems.map((item) => {
          const isActive = location.pathname === item.path;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={cn(
                "flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-300 group",
                isActive
                  ? "bg-primary/10 text-primary border border-primary/30"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted"
              )}
            >
              <item.icon
                className={cn(
                  "w-5 h-5 transition-all duration-300",
                  isActive && "text-primary text-glow-sm"
                )}
              />
              {!collapsed && (
                <span className={cn("font-medium", isActive && "text-primary")}>
                  {item.label}
                </span>
              )}
              {isActive && !collapsed && (
                <div className="ml-auto w-2 h-2 rounded-full bg-primary animate-pulse" />
              )}
            </NavLink>
          );
        })}
      </nav>

      {/* Collapse Button */}
      <div className="p-4 border-t border-sidebar-border">
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-muted-foreground hover:text-foreground hover:bg-muted transition-all duration-300"
        >
          {collapsed ? (
            <ChevronRight className="w-5 h-5" />
          ) : (
            <>
              <ChevronLeft className="w-5 h-5" />
              <span className="text-sm">Collapse</span>
            </>
          )}
        </button>
      </div>

      {/* Version */}
      {!collapsed && (
        <div className="px-4 pb-4">
          <div className="text-xs text-muted-foreground text-center">
            v1.0.0 • AI Powered
          </div>
        </div>
      )}
    </aside>
  );
}
