"use client";

import React, { useEffect, useRef, useState } from "react";
import {
  Check,
  Copy,
  Download,
  History,
  KeyRound,
  Save,
  ShieldCheck,
  Upload,
  X,
} from "lucide-react";
import { api, downloadAuthenticatedFile, extractApiError } from "@/lib/api";
import { formatBytes, formatDateTime } from "@/lib/format";
import { FileCategory, FileDetail, FolderItem } from "@/lib/types";

interface FileDetailDrawerProps {
  fileId: string | null;
  canEdit: boolean;
  canVersion: boolean;
  folders: FolderItem[];
  onClose: () => void;
  onChanged: () => void;
}

export function FileDetailDrawer({
  fileId,
  canEdit,
  canVersion,
  folders,
  onClose,
  onChanged,
}: FileDetailDrawerProps) {
  const [detail, setDetail] = useState<FileDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [name, setName] = useState("");
  const [folderId, setFolderId] = useState("");
  const [category, setCategory] = useState<FileCategory>("document");
  const [tags, setTags] = useState("");
  const [description, setDescription] = useState("");
  const [saving, setSaving] = useState(false);
  const [copied, setCopied] = useState(false);
  const [message, setMessage] = useState<{ type: "ok" | "err"; text: string } | null>(null);

  const verInputRef = useRef<HTMLInputElement | null>(null);
  const [changeNote, setChangeNote] = useState("");
  const [uploadingVersion, setUploadingVersion] = useState(false);

  const loadDetail = async (id: string) => {
    setLoading(true);
    setMessage(null);
    try {
      const res = await api.get<FileDetail>(`/files/${id}`);
      const d = res.data;
      setDetail(d);
      setName(d.name);
      setFolderId(d.folder_id || "");
      setCategory(d.category);
      setTags(d.tags.join(", "));
      setDescription(d.description || "");
    } catch (err) {
      setMessage({ type: "err", text: extractApiError(err, "Failed to load file details.") });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (fileId) loadDetail(fileId);
    else setDetail(null);
  }, [fileId]);

  if (!fileId) return null;

  const handleSaveMeta = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!detail) return;
    setSaving(true);
    setMessage(null);
    try {
      const res = await api.patch<FileDetail>(`/files/${detail.id}`, {
        name: name.trim(),
        folder_id: folderId || null,
        category,
        description,
        tags: tags
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
      });
      setDetail(res.data);
      setMessage({ type: "ok", text: "Metadata saved & audited." });
      onChanged();
    } catch (err) {
      setMessage({ type: "err", text: extractApiError(err) });
    } finally {
      setSaving(false);
    }
  };

  const handleVersionFile = async (selected: File | undefined) => {
    if (!selected || !detail) return;
    setUploadingVersion(true);
    setMessage(null);
    try {
      const form = new FormData();
      form.append("file", selected);
      if (changeNote.trim()) form.append("change_note", changeNote.trim());
      await api.post(`/files/${detail.id}/versions`, form);
      setChangeNote("");
      await loadDetail(detail.id);
      onChanged();
      setMessage({ type: "ok", text: "New encrypted version uploaded." });
    } catch (err) {
      setMessage({ type: "err", text: extractApiError(err, "Version upload failed.") });
    } finally {
      setUploadingVersion(false);
    }
  };

  const copyChecksum = () => {
    if (!detail) return;
    navigator.clipboard.writeText(detail.sha256_checksum);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-slate-950/40 backdrop-blur-xs">
      <div className="flex h-full w-full max-w-lg flex-col border-l border-slate-200 bg-white shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-100 px-6 py-4">
          <div className="min-w-0">
            <p className="text-xs font-medium uppercase tracking-wider text-indigo-600">
              File Metadata &amp; Versions
            </p>
            <h2 className="truncate text-base font-semibold text-slate-900">
              {detail?.name || "Loading..."}
            </h2>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-700"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 space-y-6 overflow-y-auto px-6 py-5">
          {loading && <p className="text-sm text-slate-500">Loading cryptographic metadata...</p>}

          {message && (
            <div
              className={`rounded-lg px-3 py-2 text-xs font-medium ${
                message.type === "ok"
                  ? "bg-emerald-50 text-emerald-700"
                  : "bg-rose-50 text-rose-700"
              }`}
            >
              {message.text}
            </div>
          )}

          {detail && (
            <>
              {/* Encryption & Integrity card */}
              <div className="rounded-xl border border-emerald-200 bg-emerald-50/50 p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-sm font-semibold text-emerald-900">
                    <ShieldCheck className="h-4 w-4 text-emerald-600" />
                    <span>
                      {detail.is_encrypted
                        ? "Server-Side AES-256-GCM Encrypted"
                        : "Unencrypted Storage"}
                    </span>
                  </div>
                  <span className="rounded-full bg-white px-2.5 py-0.5 text-xs font-semibold text-emerald-700 ring-1 ring-emerald-200">
                    v{detail.current_version}
                  </span>
                </div>
                <dl className="mt-3 grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <dt className="text-slate-500">Plaintext Size</dt>
                    <dd className="font-medium text-slate-800">{formatBytes(detail.size_bytes)}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Ciphertext Size</dt>
                    <dd className="font-medium text-slate-800">
                      {formatBytes(detail.encrypted_size_bytes)}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">MIME Type</dt>
                    <dd className="truncate font-medium text-slate-800">{detail.mime_type}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Downloads</dt>
                    <dd className="font-medium text-slate-800">{detail.download_count}</dd>
                  </div>
                </dl>
                {detail.encryption_key_id && (
                  <div className="mt-3 flex items-center gap-1.5 text-[11px] text-slate-600">
                    <KeyRound className="h-3.5 w-3.5 text-emerald-700 shrink-0" />
                    <span className="truncate font-mono">
                      Envelope DEK ID: {detail.encryption_key_id}
                    </span>
                  </div>
                )}
                <div className="mt-2 flex items-center justify-between gap-2 rounded-lg bg-white/90 px-2.5 py-1.5 ring-1 ring-emerald-200/80">
                  <span className="truncate font-mono text-[11px] text-slate-600">
                    SHA-256: {detail.sha256_checksum}
                  </span>
                  <button
                    type="button"
                    onClick={copyChecksum}
                    className="shrink-0 text-slate-500 hover:text-indigo-600"
                    title="Copy SHA-256"
                  >
                    {copied ? (
                      <Check className="h-3.5 w-3.5 text-emerald-600" />
                    ) : (
                      <Copy className="h-3.5 w-3.5" />
                    )}
                  </button>
                </div>
              </div>

              {/* Quick download button */}
              {!detail.is_deleted && (
                <button
                  type="button"
                  onClick={() => downloadAuthenticatedFile(detail.id, detail.name)}
                  className="flex w-full items-center justify-center gap-2 rounded-xl bg-slate-900 px-4 py-2.5 text-sm font-semibold text-white hover:bg-slate-800"
                >
                  <Download className="h-4 w-4" />
                  Decrypt &amp; Download Latest (v{detail.current_version})
                </button>
              )}

              {/* Editable Metadata Form */}
              <form onSubmit={handleSaveMeta} className="space-y-3">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                  Classification &amp; Metadata
                </h3>
                <div>
                  <label className="mb-1 block text-xs font-medium text-slate-700">Display Name</label>
                  <input
                    type="text"
                    disabled={!canEdit || detail.is_deleted}
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900 disabled:bg-slate-50"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="mb-1 block text-xs font-medium text-slate-700">Folder</label>
                    <select
                      disabled={!canEdit || detail.is_deleted}
                      value={folderId}
                      onChange={(e) => setFolderId(e.target.value)}
                      className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 disabled:bg-slate-50"
                    >
                      <option value="">Root Vault</option>
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
                      disabled={!canEdit || detail.is_deleted}
                      value={category}
                      onChange={(e) => setCategory(e.target.value as FileCategory)}
                      className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 disabled:bg-slate-50"
                    >
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
                <div>
                  <label className="mb-1 block text-xs font-medium text-slate-700">Tags</label>
                  <input
                    type="text"
                    disabled={!canEdit || detail.is_deleted}
                    value={tags}
                    onChange={(e) => setTags(e.target.value)}
                    placeholder="security, policy, q4"
                    className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900 disabled:bg-slate-50"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium text-slate-700">Description</label>
                  <textarea
                    rows={2}
                    disabled={!canEdit || detail.is_deleted}
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900 disabled:bg-slate-50"
                  />
                </div>
                {canEdit && !detail.is_deleted && (
                  <button
                    type="submit"
                    disabled={saving}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-60"
                  >
                    <Save className="h-3.5 w-3.5" />
                    {saving ? "Saving..." : "Save Metadata"}
                  </button>
                )}
              </form>

              {/* Version History & Upload New Version */}
              <div className="space-y-3 border-t border-slate-100 pt-4">
                <div className="flex items-center justify-between">
                  <h3 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-500">
                    <History className="h-3.5 w-3.5" />
                    Version History ({detail.versions.length})
                  </h3>
                </div>

                {canVersion && !detail.is_deleted && (
                  <div className="flex items-center gap-2 rounded-xl border border-slate-200 bg-slate-50 p-2.5">
                    <input
                      type="text"
                      value={changeNote}
                      onChange={(e) => setChangeNote(e.target.value)}
                      placeholder="Change note for next revision..."
                      className="min-w-0 flex-1 rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 text-xs text-slate-800"
                    />
                    <input
                      ref={verInputRef}
                      type="file"
                      className="hidden"
                      onChange={(e) => {
                        handleVersionFile(e.target.files?.[0]);
                        e.target.value = "";
                      }}
                    />
                    <button
                      type="button"
                      disabled={uploadingVersion}
                      onClick={() => verInputRef.current?.click()}
                      className="inline-flex shrink-0 items-center gap-1 rounded-lg bg-slate-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-slate-800 disabled:opacity-60"
                    >
                      <Upload className="h-3.5 w-3.5" />
                      {uploadingVersion ? "Uploading..." : "New Version"}
                    </button>
                  </div>
                )}

                <div className="space-y-2">
                  {detail.versions.map((v) => (
                    <div
                      key={v.id}
                      className="flex items-center justify-between gap-3 rounded-xl border border-slate-200 px-3.5 py-2.5 text-xs"
                    >
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="rounded bg-indigo-50 px-1.5 py-0.5 font-semibold text-indigo-700">
                            v{v.version_number}
                          </span>
                          <span className="font-medium text-slate-800">
                            {formatBytes(v.size_bytes)}
                          </span>
                          <span className="text-slate-400">{formatDateTime(v.created_at)}</span>
                        </div>
                        {v.change_note && (
                          <p className="mt-1 truncate text-slate-600">{v.change_note}</p>
                        )}
                        <p className="mt-0.5 truncate font-mono text-[10px] text-slate-400">
                          SHA-256: {v.sha256_checksum.slice(0, 24)}…
                        </p>
                      </div>
                      {!detail.is_deleted && (
                        <button
                          type="button"
                          onClick={() =>
                            downloadAuthenticatedFile(detail.id, detail.name, v.version_number)
                          }
                          className="rounded-lg border border-slate-200 p-1.5 text-slate-600 hover:bg-slate-50 hover:text-indigo-600"
                          title={`Download v${v.version_number}`}
                        >
                          <Download className="h-4 w-4" />
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
