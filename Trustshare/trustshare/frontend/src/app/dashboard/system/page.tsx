"use client";

import React, { useCallback, useEffect, useState } from "react";
import {
  CheckCircle2,
  Database,
  ExternalLink,
  Info,
  RefreshCw,
} from "lucide-react";
import { api, extractApiError } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { DatastoreStatus } from "@/lib/types";

export default function SystemDatastoresPage() {
  const [stores, setStores] = useState<DatastoreStatus[]>([]);
  const [checkedAt, setCheckedAt] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const probe = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get("/health/datastores");
      setStores(res.data.datastores);
      setCheckedAt(res.data.checked_at);
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    probe();
  }, [probe]);

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            Architecture &amp; Datastore Telemetry
          </h1>
          <p className="mt-0.5 text-sm text-slate-500">
            Live connectivity check across PostgreSQL, MongoDB, Redis, and AES-256-GCM Object Storage
            {checkedAt ? ` · Last checked ${formatDateTime(checkedAt)}` : ""}.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <a
            href="/docs"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1.5 rounded-xl border border-indigo-200 bg-indigo-50 px-3.5 py-2 text-xs font-semibold text-indigo-700 hover:bg-indigo-100"
          >
            <span>FastAPI Swagger /docs</span>
            <ExternalLink className="h-3.5 w-3.5" />
          </a>
          <button
            onClick={probe}
            className="inline-flex items-center gap-1.5 rounded-xl border border-slate-300 bg-white px-3.5 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Re-check
          </button>
        </div>
      </div>

      {error && (
        <p className="rounded-xl bg-rose-50 px-4 py-3 text-xs font-medium text-rose-700">{error}</p>
      )}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {loading
          ? [1, 2, 3, 4].map((i) => (
              <div
                key={i}
                className="h-40 animate-pulse rounded-2xl border border-slate-200 bg-white p-5"
              />
            ))
          : stores.map((ds) => {
              const isPrimary = ds.status === "connected";
              return (
                <div
                  key={ds.service}
                  className="rounded-2xl border border-slate-200 bg-white p-5 shadow-2xs"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2.5">
                      <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-slate-100 text-slate-700">
                        <Database className="h-4 w-4" />
                      </div>
                      <div>
                        <h2 className="text-sm font-bold uppercase tracking-wide text-slate-900">
                          {ds.service.replace("_", " ")}
                        </h2>
                        <p className="text-xs text-slate-500">{ds.engine}</p>
                      </div>
                    </div>

                    {isPrimary ? (
                      <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-emerald-50 px-2.5 py-0.5 text-xs font-semibold text-emerald-700 ring-1 ring-emerald-200">
                        <CheckCircle2 className="h-3.5 w-3.5" /> Connected
                      </span>
                    ) : (
                      <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-amber-50 px-2.5 py-0.5 text-xs font-semibold text-amber-800 ring-1 ring-amber-200">
                        <Info className="h-3.5 w-3.5" /> Fallback Active
                      </span>
                    )}
                  </div>

                  <p className="mt-3 text-xs text-slate-600">{ds.role}</p>

                  <div className="mt-4 flex flex-wrap gap-2 text-[11px]">
                    {ds.latency_ms !== undefined && (
                      <span className="rounded-md bg-slate-100 px-2 py-0.5 font-mono text-slate-700">
                        Latency: {ds.latency_ms} ms
                      </span>
                    )}
                    {ds.active_keys !== undefined && (
                      <span className="rounded-md bg-slate-100 px-2 py-0.5 font-mono text-slate-700">
                        Redis Keys: {ds.active_keys}
                      </span>
                    )}
                    {ds.audit_documents !== undefined && (
                      <span className="rounded-md bg-slate-100 px-2 py-0.5 font-mono text-slate-700">
                        Audit Docs: {ds.audit_documents}
                      </span>
                    )}
                    {ds.stored_objects !== undefined && (
                      <span className="rounded-md bg-slate-100 px-2 py-0.5 font-mono text-slate-700">
                        Encrypted Blobs: {ds.stored_objects}
                      </span>
                    )}
                    {ds.encryption && (
                      <span className="rounded-md bg-emerald-50 px-2 py-0.5 font-medium text-emerald-700">
                        {ds.encryption}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
      </div>
    </div>
  );
}
