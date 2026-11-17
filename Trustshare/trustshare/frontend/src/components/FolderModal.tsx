"use client";

import React, { useState } from "react";
import { FolderPlus, X } from "lucide-react";
import { api, extractApiError } from "@/lib/api";

const COLORS = [
  { id: "indigo", dot: "bg-indigo-600" },
  { id: "emerald", dot: "bg-emerald-600" },
  { id: "amber", dot: "bg-amber-500" },
  { id: "rose", dot: "bg-rose-600" },
  { id: "sky", dot: "bg-sky-600" },
  { id: "violet", dot: "bg-violet-600" },
  { id: "slate", dot: "bg-slate-600" },
];

interface FolderModalProps {
  open: boolean;
  parentId: string | null;
  onClose: () => void;
  onCreated: () => void;
}

export function FolderModal({ open, parentId, onClose, onCreated }: FolderModalProps) {
  const [name, setName] = useState("");
  const [color, setColor] = useState("indigo");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!open) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      await api.post("/folders", {
        name: name.trim(),
        parent_id: parentId,
        color,
      });
      setName("");
      setColor("indigo");
      onCreated();
      onClose();
    } catch (err) {
      setError(extractApiError(err, "Could not create folder."));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/50 p-4 backdrop-blur-xs">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-md rounded-2xl border border-slate-200 bg-white shadow-2xl"
      >
        <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4">
          <div className="flex items-center gap-2">
            <FolderPlus className="h-5 w-5 text-indigo-600" />
            <h2 className="text-base font-semibold text-slate-900">New Folder</h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="space-y-4 px-5 py-4">
          <div>
            <label className="mb-1 block text-xs font-medium text-slate-700">Folder Name</label>
            <input
              type="text"
              autoFocus
              required
              maxLength={180}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., Legal Contracts 2026"
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900 focus:border-indigo-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="mb-1.5 block text-xs font-medium text-slate-700">Accent Color</label>
            <div className="flex items-center gap-2.5">
              {COLORS.map((c) => (
                <button
                  key={c.id}
                  type="button"
                  onClick={() => setColor(c.id)}
                  className={`h-7 w-7 rounded-full ${c.dot} transition ${
                    color === c.id ? "ring-2 ring-offset-2 ring-slate-900 scale-110" : "opacity-70 hover:opacity-100"
                  }`}
                  aria-label={c.id}
                />
              ))}
            </div>
          </div>

          {error && (
            <p className="rounded-lg bg-rose-50 px-3 py-2 text-xs text-rose-700">{error}</p>
          )}
        </div>

        <div className="flex justify-end gap-2 border-t border-slate-100 px-5 py-3.5">
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={submitting || !name.trim()}
            className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-700 disabled:opacity-60"
          >
            {submitting ? "Creating..." : "Create Folder"}
          </button>
        </div>
      </form>
    </div>
  );
}
