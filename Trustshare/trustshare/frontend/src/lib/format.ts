import { FileCategory, UserRole } from "./types";

export function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const idx = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const val = bytes / Math.pow(1024, idx);
  return `${val >= 10 || idx === 0 ? val.toFixed(0) : val.toFixed(1)} ${units[idx]}`;
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "Never";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatRelative(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  const diffSec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (diffSec < 60) return "just now";
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  if (diffSec < 86400 * 7) return `${Math.floor(diffSec / 86400)}d ago`;
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

export const CATEGORY_META: Record<
  FileCategory,
  { label: string; badge: string }
> = {
  document: { label: "Document", badge: "bg-indigo-50 text-indigo-700 ring-indigo-200" },
  spreadsheet: { label: "Spreadsheet", badge: "bg-emerald-50 text-emerald-700 ring-emerald-200" },
  presentation: { label: "Presentation", badge: "bg-amber-50 text-amber-700 ring-amber-200" },
  image: { label: "Image", badge: "bg-rose-50 text-rose-700 ring-rose-200" },
  archive: { label: "Archive", badge: "bg-violet-50 text-violet-700 ring-violet-200" },
  code: { label: "Code / Config", badge: "bg-sky-50 text-sky-700 ring-sky-200" },
  media: { label: "Media", badge: "bg-fuchsia-50 text-fuchsia-700 ring-fuchsia-200" },
  other: { label: "Other", badge: "bg-slate-100 text-slate-700 ring-slate-200" },
};

export const ROLE_BADGE: Record<UserRole, string> = {
  admin: "bg-indigo-600 text-white",
  manager: "bg-emerald-600 text-white",
  member: "bg-slate-800 text-white",
  guest: "bg-amber-100 text-amber-900 ring-1 ring-amber-300",
};

export const FOLDER_COLOR_CLASSES: Record<string, string> = {
  indigo: "text-indigo-600 bg-indigo-50 border-indigo-100",
  emerald: "text-emerald-600 bg-emerald-50 border-emerald-100",
  amber: "text-amber-600 bg-amber-50 border-amber-100",
  rose: "text-rose-600 bg-rose-50 border-rose-100",
  sky: "text-sky-600 bg-sky-50 border-sky-100",
  violet: "text-violet-600 bg-violet-50 border-violet-100",
  slate: "text-slate-600 bg-slate-100 border-slate-200",
};
