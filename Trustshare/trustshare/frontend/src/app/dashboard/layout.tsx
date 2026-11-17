"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Activity,
  Database,
  FolderLock,
  KeyRound,
  LogOut,
  Menu,
  ShieldCheck,
  Users,
  X,
} from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { formatBytes, ROLE_BADGE } from "@/lib/format";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { user, loading, logout, can } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    if (!loading && !user) {
      router.replace("/login");
    }
  }, [loading, user, router]);

  if (loading || !user) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50">
        <div className="flex items-center gap-2 text-sm text-slate-500">
          <ShieldCheck className="h-5 w-5 animate-pulse text-indigo-600" />
          <span>Verifying session &amp; permissions...</span>
        </div>
      </div>
    );
  }

  const navItems = [
    { href: "/dashboard", label: "Encrypted Vault", icon: FolderLock, show: true },
    { href: "/dashboard/activity", label: "Audit Activity", icon: Activity, show: true },
    { href: "/dashboard/security", label: "Security & MFA", icon: KeyRound, show: true },
    {
      href: "/dashboard/admin",
      label: "Users & RBAC",
      icon: Users,
      show: can("user:read_all"),
    },
    { href: "/dashboard/system", label: "Datastore Status", icon: Database, show: true },
  ].filter((n) => n.show);

  const usedPct =
    user.storage_quota_bytes > 0
      ? Math.min(100, Math.round((user.storage_used_bytes / user.storage_quota_bytes) * 1000) / 10)
      : 0;

  const handleLogout = async () => {
    await logout();
    router.replace("/login");
  };

  const sidebarContent = (
    <div className="flex h-full flex-col justify-between bg-slate-950 text-slate-200">
      <div>
        {/* Brand */}
        <div className="flex items-center justify-between border-b border-slate-800/80 px-5 py-4">
          <Link href="/dashboard" className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-500 text-white">
              <ShieldCheck className="h-4 w-4" />
            </div>
            <div>
              <p className="text-sm font-bold tracking-tight text-white">TrustShare</p>
              <p className="text-[10px] font-medium text-emerald-400">AES-256-GCM Active</p>
            </div>
          </Link>
          <button
            onClick={() => setMobileOpen(false)}
            className="rounded-lg p-1 text-slate-400 hover:text-white lg:hidden"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Navigation */}
        <nav className="mt-4 space-y-1 px-3">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                onClick={() => setMobileOpen(false)}
                className={`flex items-center gap-3 rounded-xl px-3.5 py-2.5 text-sm font-medium transition ${
                  active
                    ? "bg-indigo-600 text-white shadow-sm"
                    : "text-slate-400 hover:bg-slate-900 hover:text-white"
                }`}
              >
                <Icon className="h-4 w-4 shrink-0" />
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>
      </div>

      {/* Bottom Quota & Profile */}
      <div className="space-y-3 border-t border-slate-800/80 p-4">
        <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-3">
          <div className="flex items-center justify-between text-[11px]">
            <span className="font-medium text-slate-300">Encrypted Quota</span>
            <span className="font-mono text-slate-400">{usedPct}%</span>
          </div>
          <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
            <div
              className="h-full rounded-full bg-indigo-500 transition-all"
              style={{ width: `${Math.max(usedPct, user.storage_used_bytes > 0 ? 2 : 0)}%` }}
            />
          </div>
          <p className="mt-1.5 text-[11px] text-slate-400">
            {formatBytes(user.storage_used_bytes)} of {formatBytes(user.storage_quota_bytes)}
          </p>
        </div>

        <div className="flex items-center justify-between gap-2 rounded-xl bg-slate-900/60 px-3 py-2.5">
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <p className="truncate text-xs font-semibold text-white">{user.full_name}</p>
            </div>
            <p className="truncate text-[11px] text-slate-400">{user.email}</p>
            <span
              className={`mt-1 inline-block rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
                ROLE_BADGE[user.role]
              }`}
            >
              {user.role}
            </span>
          </div>
          <button
            onClick={handleLogout}
            title="Sign out & revoke session"
            className="rounded-lg p-2 text-slate-400 hover:bg-slate-800 hover:text-rose-400"
          >
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <div className="flex min-h-screen bg-slate-50">
      {/* Desktop Sidebar */}
      <aside className="hidden w-64 shrink-0 lg:block">{sidebarContent}</aside>

      {/* Mobile Drawer */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 flex lg:hidden">
          <div className="w-64 shrink-0">{sidebarContent}</div>
          <div className="flex-1 bg-slate-950/50" onClick={() => setMobileOpen(false)} />
        </div>
      )}

      {/* Main Column */}
      <div className="flex min-w-0 flex-1 flex-col">
        {/* Mobile Top Bar */}
        <header className="flex items-center justify-between border-b border-slate-200 bg-white px-4 py-3 lg:hidden">
          <button
            onClick={() => setMobileOpen(true)}
            className="rounded-lg p-1.5 text-slate-600 hover:bg-slate-100"
          >
            <Menu className="h-5 w-5" />
          </button>
          <span className="text-sm font-bold text-slate-900">TrustShare</span>
          <span
            className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase ${
              ROLE_BADGE[user.role]
            }`}
          >
            {user.role}
          </span>
        </header>

        <main className="flex-1 p-5 lg:p-8">{children}</main>
      </div>
    </div>
  );
}
