"use client";

import React, { useCallback, useEffect, useState } from "react";
import { RefreshCw, ShieldAlert, ShieldCheck } from "lucide-react";
import { api, extractApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { formatDateTime } from "@/lib/format";
import { AuditEvent } from "@/lib/types";

export default function AuditActivityPage() {
  const { can } = useAuth();
  const canAll = can("audit:read_all");

  const [scope, setScope] = useState<"own" | "all">(canAll ? "all" : "own");
  const [category, setCategory] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [mode, setMode] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadLogs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, string | number> = { scope, limit: 100 };
      if (category) params.category = category;
      if (statusFilter) params.status = statusFilter;
      const res = await api.get("/users/audit-logs", { params });
      setEvents(res.data.items);
      setTotal(res.data.total);
      setMode(res.data.datastore_mode);
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setLoading(false);
    }
  }, [scope, category, statusFilter]);

  useEffect(() => {
    loadLogs();
  }, [loadLogs]);

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            Immutable Audit &amp; Activity Log
          </h1>
          <p className="mt-0.5 text-sm text-slate-500">
            Every authentication, upload, version, download, and blocked security probe ({total} events · mode:{" "}
            <span className="font-mono text-xs text-slate-700">{mode || "..."}</span>).
          </p>
        </div>

        <button
          onClick={loadLogs}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-300 bg-white px-3.5 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2.5 rounded-2xl border border-slate-200 bg-white p-4">
        {canAll && (
          <div className="flex rounded-lg bg-slate-100 p-1 text-xs font-semibold">
            <button
              onClick={() => setScope("all")}
              className={`rounded-md px-3 py-1 ${
                scope === "all" ? "bg-white text-slate-900 shadow-2xs" : "text-slate-600"
              }`}
            >
              Organization-Wide
            </button>
            <button
              onClick={() => setScope("own")}
              className={`rounded-md px-3 py-1 ${
                scope === "own" ? "bg-white text-slate-900 shadow-2xs" : "text-slate-600"
              }`}
            >
              My Activity
            </button>
          </div>
        )}

        <select
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700"
        >
          <option value="">All Categories</option>
          <option value="auth">Authentication</option>
          <option value="file">File Operations</option>
          <option value="folder">Folder Operations</option>
          <option value="security">Security Events</option>
          <option value="admin">Admin / RBAC</option>
        </select>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700"
        >
          <option value="">All Outcomes</option>
          <option value="success">Success</option>
          <option value="blocked">Blocked</option>
          <option value="failure">Failure</option>
        </select>
      </div>

      {error && (
        <p className="rounded-xl bg-rose-50 px-4 py-3 text-xs font-medium text-rose-700">{error}</p>
      )}

      {/* Event Table */}
      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-2xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-100 bg-slate-50 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-4 py-3">Timestamp</th>
                <th className="px-4 py-3">Event</th>
                <th className="px-4 py-3">Actor</th>
                <th className="px-4 py-3">Resource</th>
                <th className="px-4 py-3">Outcome</th>
                <th className="px-4 py-3">IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading ? (
                <tr>
                  <td colSpan={6} className="px-4 py-10 text-center text-slate-400">
                    Loading audit events...
                  </td>
                </tr>
              ) : events.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-10 text-center text-slate-400">
                    No matching audit records found.
                  </td>
                </tr>
              ) : (
                events.map((ev) => (
                  <tr key={ev.event_id} className="hover:bg-slate-50/70">
                    <td className="whitespace-nowrap px-4 py-3 text-slate-500">
                      {formatDateTime(ev.timestamp)}
                    </td>
                    <td className="px-4 py-3">
                      <span className="font-mono font-semibold text-slate-900">{ev.action}</span>
                      <span className="ml-2 rounded bg-slate-100 px-1.5 py-0.5 text-[10px] uppercase text-slate-500">
                        {ev.category}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-700">
                      {ev.actor_email || "anonymous"}
                      {ev.actor_role && (
                        <span className="ml-1.5 text-[10px] uppercase text-indigo-600">
                          ({ev.actor_role})
                        </span>
                      )}
                    </td>
                    <td className="max-w-xs truncate px-4 py-3 text-slate-600">
                      {ev.resource_name || "—"}
                    </td>
                    <td className="px-4 py-3">
                      {ev.status === "success" ? (
                        <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2 py-0.5 font-medium text-emerald-700">
                          <ShieldCheck className="h-3 w-3" /> success
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded-full bg-rose-50 px-2 py-0.5 font-medium text-rose-700">
                          <ShieldAlert className="h-3 w-3" /> {ev.status}
                        </span>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 font-mono text-slate-400">
                      {ev.ip_address || "internal"}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
