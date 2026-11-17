"use client";

import React, { useCallback, useEffect, useState } from "react";
import {
  ChevronRight,
  Download,
  FileText,
  Folder,
  FolderPlus,
  HardDrive,
  History,
  Info,
  Lock,
  RotateCcw,
  Search,
  ShieldAlert,
  Star,
  Trash2,
  UploadCloud,
} from "lucide-react";
import { api, downloadAuthenticatedFile, extractApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import {
  CATEGORY_META,
  FOLDER_COLOR_CLASSES,
  formatBytes,
  formatRelative,
} from "@/lib/format";
import {
  BreadcrumbItem,
  DashboardSummary,
  FileCategory,
  FileItem,
  FolderItem,
} from "@/lib/types";
import { UploadModal } from "@/components/UploadModal";
import { FolderModal } from "@/components/FolderModal";
import { FileDetailDrawer } from "@/components/FileDetailDrawer";

type ViewMode = "folder" | "all" | "starred" | "trash" | "shared" | "org";

export default function FileManagementDashboard() {
  const { user, can, refreshUser } = useAuth();
  const isGuest = user?.role === "guest";
  const isAdmin = user?.role === "admin";

  const [view, setView] = useState<ViewMode>(isGuest ? "shared" : "folder");
  const [currentFolderId, setCurrentFolderId] = useState<string | null>(null);
  const [breadcrumbs, setBreadcrumbs] = useState<BreadcrumbItem[]>([]);
  const [folders, setFolders] = useState<FolderItem[]>([]);
  const [allFolders, setAllFolders] = useState<FolderItem[]>([]);
  const [files, setFiles] = useState<FileItem[]>([]);
  const [summary, setSummary] = useState<DashboardSummary | null>(null);

  const [search, setSearch] = useState("");
  const [category, setCategory] = useState<"" | FileCategory>("");
  const [sortBy, setSortBy] = useState("updated_at");
  const [loading, setLoading] = useState(true);
  const [banner, setBanner] = useState<{ type: "ok" | "err"; text: string } | null>(null);

  const [uploadOpen, setUploadOpen] = useState(false);
  const [folderOpen, setFolderOpen] = useState(false);
  const [selectedFileId, setSelectedFileId] = useState<string | null>(null);

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const fileParams: Record<string, string> = {
        view,
        sort_by: sortBy,
        sort_dir: sortBy === "name" ? "asc" : "desc",
      };
      if (view === "folder" && currentFolderId) fileParams.folder_id = currentFolderId;
      if (search.trim()) fileParams.q = search.trim();
      if (category) fileParams.category = category;

      const [sumRes, fileRes, allFoldRes] = await Promise.all([
        api.get<DashboardSummary>("/files/summary"),
        api.get<{ items: FileItem[]; total: number }>("/files", { params: fileParams }),
        isGuest
          ? Promise.resolve({ data: [] as FolderItem[] })
          : api.get<FolderItem[]>("/folders", { params: { all_folders: true } }),
      ]);

      setSummary(sumRes.data);
      setFiles(fileRes.data.items);
      setAllFolders(allFoldRes.data);

      if (view === "folder" && !isGuest) {
        const foldRes = await api.get<FolderItem[]>("/folders", {
          params: currentFolderId ? { parent_id: currentFolderId } : {},
        });
        setFolders(foldRes.data);
        if (currentFolderId) {
          const bcRes = await api.get<BreadcrumbItem[]>(
            `/folders/${currentFolderId}/breadcrumbs`
          );
          setBreadcrumbs(bcRes.data);
        } else {
          setBreadcrumbs([]);
        }
      } else {
        setFolders([]);
        setBreadcrumbs([]);
      }
    } catch (err) {
      setBanner({ type: "err", text: extractApiError(err, "Failed to load files.") });
    } finally {
      setLoading(false);
    }
  }, [view, currentFolderId, search, category, sortBy, isGuest]);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  const handleRefreshAfterMutation = async () => {
    await Promise.all([fetchAll(), refreshUser()]);
  };

  const toggleStar = async (file: FileItem) => {
    try {
      await api.patch(`/files/${file.id}`, { is_starred: !file.is_starred });
      fetchAll();
    } catch (err) {
      setBanner({ type: "err", text: extractApiError(err) });
    }
  };

  const trashFile = async (file: FileItem) => {
    try {
      await api.delete(`/files/${file.id}`);
      setBanner({ type: "ok", text: `"${file.name}" moved to Trash.` });
      handleRefreshAfterMutation();
    } catch (err) {
      setBanner({ type: "err", text: extractApiError(err) });
    }
  };

  const restoreFile = async (file: FileItem) => {
    try {
      await api.post(`/files/${file.id}/restore`);
      setBanner({ type: "ok", text: `"${file.name}" restored to vault.` });
      handleRefreshAfterMutation();
    } catch (err) {
      setBanner({ type: "err", text: extractApiError(err) });
    }
  };

  const purgeFile = async (file: FileItem) => {
    if (
      !window.confirm(
        `Permanently erase "${file.name}" and shred its wrapped AES-256 DEK(s)? This cannot be undone.`
      )
    ) {
      return;
    }
    try {
      await api.delete(`/files/${file.id}`, { params: { permanent: true } });
      setBanner({ type: "ok", text: `"${file.name}" and its encryption keys permanently shredded.` });
      handleRefreshAfterMutation();
    } catch (err) {
      setBanner({ type: "err", text: extractApiError(err) });
    }
  };

  const deleteFolder = async (folder: FolderItem) => {
    if (
      !window.confirm(
        `Delete folder "${folder.name}"? Any files inside will be relocated safely to its parent.`
      )
    ) {
      return;
    }
    try {
      await api.delete(`/folders/${folder.id}`);
      setBanner({ type: "ok", text: `Folder "${folder.name}" deleted.` });
      fetchAll();
    } catch (err) {
      setBanner({ type: "err", text: extractApiError(err) });
    }
  };

  const canUpload = can("file:upload");
  const canFolder = can("folder:manage");
  const canEdit = can("file:update");
  const canVersion = can("file:version");
  const canDelete = can("file:delete");

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      {/* Header Row */}
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            File Management Vault
          </h1>
          <p className="mt-0.5 text-sm text-slate-500">
            {isGuest
              ? "Read-only external guest view — authorized files decrypt in memory on download."
              : "Organize, version, and protect sensitive documents with per-file AES-256-GCM encryption."}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {canFolder && (
            <button
              onClick={() => setFolderOpen(true)}
              className="inline-flex items-center gap-2 rounded-xl border border-slate-300 bg-white px-3.5 py-2.5 text-sm font-medium text-slate-700 shadow-2xs hover:bg-slate-50"
            >
              <FolderPlus className="h-4 w-4 text-slate-500" />
              New Folder
            </button>
          )}
          {canUpload ? (
            <button
              onClick={() => setUploadOpen(true)}
              className="inline-flex items-center gap-2 rounded-xl bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700"
            >
              <UploadCloud className="h-4 w-4" />
              Upload &amp; Encrypt
            </button>
          ) : (
            <span className="inline-flex items-center gap-1.5 rounded-xl bg-amber-50 px-3 py-2 text-xs font-medium text-amber-800 ring-1 ring-amber-200">
              <ShieldAlert className="h-4 w-4" />
              Read-Only Role (Uploads Restricted)
            </span>
          )}
        </div>
      </div>

      {/* Status banner */}
      {banner && (
        <div
          className={`flex items-center justify-between rounded-xl px-4 py-2.5 text-xs font-medium ${
            banner.type === "ok"
              ? "bg-emerald-50 text-emerald-800 ring-1 ring-emerald-200"
              : "bg-rose-50 text-rose-800 ring-1 ring-rose-200"
          }`}
        >
          <span>{banner.text}</span>
          <button onClick={() => setBanner(null)} className="ml-4 underline">
            Dismiss
          </button>
        </div>
      )}

      {/* KPI Summary Strip */}
      {summary && (
        <div className="grid grid-cols-2 gap-3.5 lg:grid-cols-4">
          <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-2xs">
            <div className="flex items-center justify-between text-xs font-medium text-slate-500">
              <span>Encrypted Files</span>
              <Lock className="h-4 w-4 text-emerald-600" />
            </div>
            <p className="mt-2 text-2xl font-bold text-slate-900">
              {summary.encrypted_files}
              <span className="ml-1.5 text-xs font-normal text-emerald-600">
                100% AES-256
              </span>
            </p>
            <p className="mt-0.5 text-xs text-slate-400">
              Across {summary.total_folders} folders
            </p>
          </div>

          <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-2xs">
            <div className="flex items-center justify-between text-xs font-medium text-slate-500">
              <span>Vault Storage Used</span>
              <HardDrive className="h-4 w-4 text-indigo-600" />
            </div>
            <p className="mt-2 text-2xl font-bold text-slate-900">
              {formatBytes(summary.storage_used_bytes)}
            </p>
            <p className="mt-0.5 text-xs text-slate-400">
              of {formatBytes(summary.storage_quota_bytes)} quota ({summary.storage_used_pct}%)
            </p>
          </div>

          <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-2xs">
            <div className="flex items-center justify-between text-xs font-medium text-slate-500">
              <span>Tracked Versions</span>
              <History className="h-4 w-4 text-violet-600" />
            </div>
            <p className="mt-2 text-2xl font-bold text-slate-900">{summary.total_versions}</p>
            <p className="mt-0.5 text-xs text-slate-400">
              SHA-256 verified revisions
            </p>
          </div>

          <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-2xs">
            <div className="flex items-center justify-between text-xs font-medium text-slate-500">
              <span>Audited Downloads</span>
              <Download className="h-4 w-4 text-sky-600" />
            </div>
            <p className="mt-2 text-2xl font-bold text-slate-900">{summary.total_downloads}</p>
            <p className="mt-0.5 text-xs text-slate-400">
              {summary.starred_files} starred · {summary.trashed_files} in trash
            </p>
          </div>
        </div>
      )}

      {/* View Tabs + Search + Filters */}
      <div className="flex flex-col gap-3 rounded-2xl border border-slate-200 bg-white p-4 shadow-2xs lg:flex-row lg:items-center lg:justify-between">
        {/* View pills */}
        <div className="flex flex-wrap items-center gap-1.5">
          {!isGuest && (
            <>
              {(
                [
                  { id: "folder", label: "Folders & Root" },
                  { id: "all", label: "All My Files" },
                  { id: "starred", label: "Starred" },
                  { id: "trash", label: `Trash${summary?.trashed_files ? ` (${summary.trashed_files})` : ""}` },
                ] as { id: ViewMode; label: string }[]
              ).map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => {
                    setView(tab.id);
                    if (tab.id !== "folder") setCurrentFolderId(null);
                  }}
                  className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                    view === tab.id
                      ? "bg-slate-900 text-white"
                      : "text-slate-600 hover:bg-slate-100"
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </>
          )}
          {isGuest && (
            <span className="rounded-lg bg-slate-900 px-3 py-1.5 text-xs font-semibold text-white">
              Shared With Me
            </span>
          )}
          {isAdmin && (
            <button
              onClick={() => {
                setView("org");
                setCurrentFolderId(null);
              }}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                view === "org"
                  ? "bg-indigo-600 text-white"
                  : "text-indigo-600 hover:bg-indigo-50"
              }`}
            >
              All Org Files (Admin)
            </button>
          )}
        </div>

        {/* Search + Category + Sort */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative min-w-[200px] flex-1 sm:flex-initial">
            <Search className="pointer-events-none absolute top-2.5 left-3 h-3.5 w-3.5 text-slate-400" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search files, ext, notes..."
              className="w-full rounded-lg border border-slate-200 bg-slate-50 py-1.5 pr-3 pl-8 text-xs text-slate-800 focus:border-indigo-500 focus:bg-white focus:outline-none"
            />
          </div>

          <select
            value={category}
            onChange={(e) => setCategory(e.target.value as "" | FileCategory)}
            className="rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700"
          >
            <option value="">All Categories</option>
            <option value="document">Documents</option>
            <option value="spreadsheet">Spreadsheets</option>
            <option value="presentation">Presentations</option>
            <option value="image">Images</option>
            <option value="code">Code / Config</option>
            <option value="archive">Archives</option>
            <option value="media">Media</option>
            <option value="other">Other</option>
          </select>

          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            className="rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700"
          >
            <option value="updated_at">Recently Modified</option>
            <option value="name">Name (A–Z)</option>
            <option value="size_bytes">Largest Size</option>
            <option value="download_count">Most Downloaded</option>
          </select>
        </div>
      </div>

      {/* Breadcrumbs when inside Folder view */}
      {view === "folder" && !isGuest && (
        <div className="flex items-center gap-1.5 text-xs font-medium text-slate-600">
          <button
            onClick={() => setCurrentFolderId(null)}
            className={`rounded px-2 py-1 hover:bg-slate-200/60 ${
              !currentFolderId ? "font-semibold text-slate-900" : ""
            }`}
          >
            Root Vault
          </button>
          {breadcrumbs.map((bc) => (
            <React.Fragment key={bc.id}>
              <ChevronRight className="h-3.5 w-3.5 text-slate-400" />
              <button
                onClick={() => setCurrentFolderId(bc.id)}
                className={`rounded px-2 py-1 hover:bg-slate-200/60 ${
                  currentFolderId === bc.id ? "font-semibold text-indigo-700" : ""
                }`}
              >
                {bc.name}
              </button>
            </React.Fragment>
          ))}
        </div>
      )}

      {/* Folder Cards */}
      {view === "folder" && folders.length > 0 && (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {folders.map((folder) => {
            const colorCls =
              FOLDER_COLOR_CLASSES[folder.color] || FOLDER_COLOR_CLASSES.indigo;
            return (
              <div
                key={folder.id}
                onClick={() => setCurrentFolderId(folder.id)}
                className="group flex cursor-pointer items-center justify-between rounded-2xl border border-slate-200 bg-white p-3.5 shadow-2xs transition hover:border-indigo-300 hover:shadow-sm"
              >
                <div className="flex min-w-0 items-center gap-3">
                  <div
                    className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border ${colorCls}`}
                  >
                    <Folder className="h-5 w-5" />
                  </div>
                  <div className="min-w-0">
                    <p className="truncate text-sm font-semibold text-slate-900 group-hover:text-indigo-700">
                      {folder.name}
                    </p>
                    <p className="text-xs text-slate-500">
                      {folder.file_count} {folder.file_count === 1 ? "file" : "files"}
                    </p>
                  </div>
                </div>
                {canFolder && (
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      deleteFolder(folder);
                    }}
                    title="Delete folder"
                    className="rounded-lg p-1.5 text-slate-300 opacity-0 transition group-hover:opacity-100 hover:bg-rose-50 hover:text-rose-600"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Files Table */}
      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-2xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-slate-100 bg-slate-50/80 text-xs font-semibold uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-5 py-3">File</th>
                <th className="px-4 py-3">Category</th>
                <th className="px-4 py-3">Protection</th>
                <th className="px-4 py-3">Size / Ver</th>
                <th className="px-4 py-3">Updated</th>
                <th className="px-5 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading ? (
                <tr>
                  <td colSpan={6} className="px-5 py-12 text-center text-sm text-slate-400">
                    Loading encrypted repository...
                  </td>
                </tr>
              ) : files.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-5 py-12 text-center">
                    <FileText className="mx-auto h-8 w-8 text-slate-300" />
                    <p className="mt-2 text-sm font-medium text-slate-700">
                      No files in this view
                    </p>
                    <p className="mt-0.5 text-xs text-slate-400">
                      {canUpload
                        ? 'Click "Upload & Encrypt" above or navigate into a folder.'
                        : "Files shared with your account will appear here."}
                    </p>
                  </td>
                </tr>
              ) : (
                files.map((file) => {
                  const cat = CATEGORY_META[file.category] || CATEGORY_META.other;
                  return (
                    <tr
                      key={file.id}
                      className="transition hover:bg-slate-50/80"
                    >
                      <td className="px-5 py-3.5">
                        <div className="flex items-center gap-3">
                          {canEdit && !file.is_deleted && (
                            <button
                              onClick={() => toggleStar(file)}
                              className="text-slate-300 hover:text-amber-500"
                              title="Toggle star"
                            >
                              <Star
                                className={`h-4 w-4 ${
                                  file.is_starred
                                    ? "fill-amber-400 text-amber-400"
                                    : ""
                                }`}
                              />
                            </button>
                          )}
                          <div className="min-w-0">
                            <button
                              onClick={() => setSelectedFileId(file.id)}
                              className="block max-w-xs truncate text-left font-medium text-slate-900 hover:text-indigo-600 lg:max-w-md"
                            >
                              {file.name}
                            </button>
                            <div className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[11px] text-slate-400">
                              {view === "org" && file.owner_email && (
                                <span className="text-slate-500">{file.owner_email} ·</span>
                              )}
                              <span className="font-mono">
                                sha256:{file.sha256_checksum.slice(0, 12)}…
                              </span>
                              {file.tags.slice(0, 3).map((t) => (
                                <span
                                  key={t}
                                  className="rounded bg-slate-100 px-1.5 py-0.2 text-[10px] text-slate-600"
                                >
                                  #{t}
                                </span>
                              ))}
                            </div>
                          </div>
                        </div>
                      </td>

                      <td className="px-4 py-3.5">
                        <span
                          className={`inline-flex rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset ${cat.badge}`}
                        >
                          {cat.label}
                        </span>
                      </td>

                      <td className="px-4 py-3.5">
                        <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2.5 py-0.5 text-xs font-medium text-emerald-700 ring-1 ring-emerald-200">
                          <Lock className="h-3 w-3" />
                          AES-256-GCM
                        </span>
                      </td>

                      <td className="px-4 py-3.5 text-xs text-slate-700">
                        <span className="font-medium">{formatBytes(file.size_bytes)}</span>
                        <span className="ml-1.5 rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] text-slate-600">
                          v{file.current_version}
                        </span>
                      </td>

                      <td className="px-4 py-3.5 text-xs text-slate-500">
                        {formatRelative(file.updated_at)}
                      </td>

                      <td className="px-5 py-3.5">
                        <div className="flex items-center justify-end gap-1">
                          {!file.is_deleted ? (
                            <>
                              <button
                                onClick={() => setSelectedFileId(file.id)}
                                title="Inspect metadata & versions"
                                className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 hover:text-indigo-600"
                              >
                                <Info className="h-4 w-4" />
                              </button>
                              <button
                                onClick={() => downloadAuthenticatedFile(file.id, file.name)}
                                title="Decrypt & download"
                                className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 hover:text-emerald-600"
                              >
                                <Download className="h-4 w-4" />
                              </button>
                              {canDelete && (
                                <button
                                  onClick={() => trashFile(file)}
                                  title="Move to trash"
                                  className="rounded-lg p-1.5 text-slate-400 hover:bg-rose-50 hover:text-rose-600"
                                >
                                  <Trash2 className="h-4 w-4" />
                                </button>
                              )}
                            </>
                          ) : (
                            <>
                              <button
                                onClick={() => restoreFile(file)}
                                title="Restore file"
                                className="inline-flex items-center gap-1 rounded-lg bg-emerald-50 px-2.5 py-1 text-xs font-medium text-emerald-700 hover:bg-emerald-100"
                              >
                                <RotateCcw className="h-3.5 w-3.5" />
                                Restore
                              </button>
                              <button
                                onClick={() => purgeFile(file)}
                                title="Shred keys & erase forever"
                                className="inline-flex items-center gap-1 rounded-lg bg-rose-50 px-2.5 py-1 text-xs font-medium text-rose-700 hover:bg-rose-100"
                              >
                                <Trash2 className="h-3.5 w-3.5" />
                                Shred
                              </button>
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modals & Metadata Drawer */}
      <UploadModal
        open={uploadOpen}
        onClose={() => setUploadOpen(false)}
        onUploaded={handleRefreshAfterMutation}
        currentFolderId={view === "folder" ? currentFolderId : null}
        folders={allFolders}
      />

      <FolderModal
        open={folderOpen}
        parentId={view === "folder" ? currentFolderId : null}
        onClose={() => setFolderOpen(false)}
        onCreated={fetchAll}
      />

      <FileDetailDrawer
        fileId={selectedFileId}
        canEdit={canEdit}
        canVersion={canVersion}
        folders={allFolders}
        onClose={() => setSelectedFileId(null)}
        onChanged={handleRefreshAfterMutation}
      />
    </div>
  );
}
