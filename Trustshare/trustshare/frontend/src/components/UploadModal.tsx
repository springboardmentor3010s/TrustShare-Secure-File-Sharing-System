"use client";

import React, { useRef, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Lock,
  ShieldCheck,
  UploadCloud,
  X,
} from "lucide-react";
import { api, extractApiError } from "@/lib/api";
import { formatBytes } from "@/lib/format";
import { FileCategory, FolderItem } from "@/lib/types";

interface QueuedFile {
  id: string;
  file: File;
  progress: number;
  status: "pending" | "uploading" | "done" | "error";
  error?: string;
  sha256?: string;
}

interface UploadModalProps {
  open: boolean;
  onClose: () => void;
  onUploaded: () => void;
  currentFolderId: string | null;
  folders: FolderItem[];
}

export function UploadModal({
  open,
  onClose,
  onUploaded,
  currentFolderId,
  folders,
}: UploadModalProps) {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [queue, setQueue] = useState<QueuedFile[]>([]);
  const [dragActive, setDragActive] = useState(false);
  const [folderId, setFolderId] = useState<string>(currentFolderId || "");
  const [category, setCategory] = useState<"" | FileCategory>("");
  const [tags, setTags] = useState("");
  const [description, setDescription] = useState("");
  const [running, setRunning] = useState(false);

  React.useEffect(() => {
    setFolderId(currentFolderId || "");
  }, [currentFolderId, open]);

  if (!open) return null;

  const addFiles = (list: FileList | null) => {
    if (!list) return;
    const added: QueuedFile[] = Array.from(list).map((f) => ({
      id: `${f.name}-${f.size}-${Math.random().toString(36).slice(2, 8)}`,
      file: f,
      progress: 0,
      status: "pending",
    }));
    setQueue((prev) => [...prev, ...added]);
  };

  const removeItem = (id: string) => {
    setQueue((prev) => prev.filter((item) => item.id !== id));
  };

  const handleUploadAll = async () => {
    const pending = queue.filter((q) => q.status === "pending" || q.status === "error");
    if (pending.length === 0) return;

    setRunning(true);
    let anySucceeded = false;

    for (const item of pending) {
      setQueue((prev) =>
        prev.map((q) => (q.id === item.id ? { ...q, status: "uploading", progress: 5, error: undefined } : q))
      );

      const form = new FormData();
      form.append("file", item.file);
      if (folderId) form.append("folder_id", folderId);
      if (category) form.append("category", category);
      if (tags.trim()) form.append("tags", tags.trim());
      if (description.trim()) form.append("description", description.trim());

      try {
        const res = await api.post("/files/upload", form, {
          onUploadProgress: (evt) => {
            if (evt.total) {
              const pct = Math.round((evt.loaded / evt.total) * 100);
              setQueue((prev) =>
                prev.map((q) => (q.id === item.id ? { ...q, progress: pct } : q))
              );
            }
          },
        });
        anySucceeded = true;
        setQueue((prev) =>
          prev.map((q) =>
            q.id === item.id
              ? { ...q, status: "done", progress: 100, sha256: res.data.sha256_checksum }
              : q
          )
        );
      } catch (err) {
        const msg = extractApiError(err, "Upload rejected.");
        setQueue((prev) =>
          prev.map((q) => (q.id === item.id ? { ...q, status: "error", error: msg } : q))
        );
      }
    }

    setRunning(false);
    if (anySucceeded) {
      onUploaded();
    }
  };

  const handleClose = () => {
    if (running) return;
    setQueue([]);
    setCategory("");
    setTags("");
    setDescription("");
    onClose();
  };

  const pendingCount = queue.filter((q) => q.status === "pending" || q.status === "error").length;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/50 p-4 backdrop-blur-xs">
      <div className="w-full max-w-xl rounded-2xl border border-slate-200 bg-white shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-100 px-6 py-4">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-indigo-600 text-white">
              <Lock className="h-4 w-4" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-slate-900">Secure Encrypted Upload</h2>
              <p className="text-xs text-slate-500">
                Magic-byte validated, SHA-256 hashed &amp; AES-256-GCM encrypted server-side
              </p>
            </div>
          </div>
          <button
            onClick={handleClose}
            disabled={running}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-600"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Body */}
        <div className="space-y-4 px-6 py-5">
          {/* Dropzone */}
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragActive(true);
            }}
            onDragLeave={() => setDragActive(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragActive(false);
              addFiles(e.dataTransfer.files);
            }}
            onClick={() => inputRef.current?.click()}
            className={`cursor-pointer rounded-xl border-2 border-dashed p-6 text-center transition ${
              dragActive
                ? "border-indigo-500 bg-indigo-50/70"
                : "border-slate-300 bg-slate-50/60 hover:border-indigo-400 hover:bg-slate-50"
            }`}
          >
            <input
              ref={inputRef}
              type="file"
              multiple
              className="hidden"
              onChange={(e) => {
                addFiles(e.target.files);
                e.target.value = "";
              }}
            />
            <UploadCloud className="mx-auto h-8 w-8 text-indigo-600" />
            <p className="mt-2 text-sm font-medium text-slate-800">
              Drop files here or <span className="text-indigo-600 underline">browse from device</span>
            </p>
            <p className="mt-1 text-xs text-slate-500">
              Max 50 MB per file · Executables (.exe, .bat, .dll, .php, ELF) and spoofed headers blocked automatically
            </p>
          </div>

          {/* Metadata selectors */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-700">Destination Folder</label>
              <select
                value={folderId}
                onChange={(e) => setFolderId(e.target.value)}
                className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none"
              >
                <option value="">Root Vault (No Folder)</option>
                {folders.map((f) => (
                  <option key={f.id} value={f.id}>
                    {f.name}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-700">Category</label>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value as "" | FileCategory)}
                className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none"
              >
                <option value="">Auto-detect from file type</option>
                <option value="document">Document</option>
                <option value="spreadsheet">Spreadsheet</option>
                <option value="presentation">Presentation</option>
                <option value="image">Image</option>
                <option value="code">Code / Config</option>
                <option value="archive">Archive</option>
                <option value="media">Media</option>
                <option value="other">Other</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-700">
                Tags <span className="font-normal text-slate-400">(comma-separated)</span>
              </label>
              <input
                type="text"
                value={tags}
                onChange={(e) => setTags(e.target.value)}
                placeholder="confidential, q4, contract"
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-700">
                Note / Description <span className="font-normal text-slate-400">(optional)</span>
              </label>
              <input
                type="text"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Purpose or classification..."
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-800 focus:border-indigo-500 focus:outline-none"
              />
            </div>
          </div>

          {/* File queue */}
          {queue.length > 0 && (
            <div className="max-h-52 space-y-2 overflow-y-auto rounded-xl border border-slate-200 bg-slate-50 p-3">
              {queue.map((item) => (
                <div
                  key={item.id}
                  className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs"
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="min-w-0 flex-1">
                      <p className="truncate font-medium text-slate-800">{item.file.name}</p>
                      <p className="text-slate-500">{formatBytes(item.file.size)}</p>
                    </div>
                    {item.status === "done" && (
                      <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2 py-0.5 font-medium text-emerald-700">
                        <CheckCircle2 className="h-3.5 w-3.5" /> AES-256 Encrypted
                      </span>
                    )}
                    {item.status === "error" && (
                      <span className="inline-flex items-center gap-1 rounded-full bg-rose-50 px-2 py-0.5 font-medium text-rose-700">
                        <AlertTriangle className="h-3.5 w-3.5" /> Blocked
                      </span>
                    )}
                    {item.status === "pending" && !running && (
                      <button
                        onClick={() => removeItem(item.id)}
                        className="text-slate-400 hover:text-slate-700"
                      >
                        <X className="h-4 w-4" />
                      </button>
                    )}
                  </div>
                  {item.status === "uploading" && (
                    <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-slate-100">
                      <div
                        className="h-full rounded-full bg-indigo-600 transition-all"
                        style={{ width: `${item.progress}%` }}
                      />
                    </div>
                  )}
                  {item.sha256 && (
                    <p className="mt-1 truncate font-mono text-[11px] text-slate-400">
                      SHA-256: {item.sha256}
                    </p>
                  )}
                  {item.error && <p className="mt-1 text-rose-600">{item.error}</p>}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-slate-100 bg-slate-50/70 px-6 py-3.5 rounded-b-2xl">
          <div className="flex items-center gap-1.5 text-xs text-slate-500">
            <ShieldCheck className="h-4 w-4 text-emerald-600" />
            <span>Unique per-file 256-bit DEK</span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleClose}
              disabled={running}
              className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
            >
              {queue.some((q) => q.status === "done") && pendingCount === 0 ? "Done" : "Cancel"}
            </button>
            {pendingCount > 0 && (
              <button
                onClick={handleUploadAll}
                disabled={running}
                className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-700 disabled:opacity-60"
              >
                {running ? "Encrypting & Storing..." : `Encrypt & Upload (${pendingCount})`}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
