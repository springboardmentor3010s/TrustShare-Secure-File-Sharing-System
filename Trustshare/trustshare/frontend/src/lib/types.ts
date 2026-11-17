export type UserRole = "admin" | "manager" | "member" | "guest";

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: UserRole;
  permissions: string[];
  is_active: boolean;
  is_verified: boolean;
  mfa_enabled: boolean;
  storage_quota_bytes: number;
  storage_used_bytes: number;
  last_login_at: string | null;
  created_at: string;
}

export interface AuthResponse {
  mfa_required: boolean;
  mfa_token?: string | null;
  access_token?: string | null;
  refresh_token?: string | null;
  token_type: string;
  expires_in?: number | null;
  user?: User | null;
}

export interface SessionItem {
  id: string;
  ip_address: string | null;
  user_agent: string | null;
  is_revoked: boolean;
  is_current: boolean;
  expires_at: string;
  last_seen_at: string;
  created_at: string;
}

export interface FolderItem {
  id: string;
  owner_id: string;
  parent_id: string | null;
  name: string;
  color: string;
  file_count: number;
  created_at: string;
  updated_at: string;
}

export interface BreadcrumbItem {
  id: string;
  name: string;
}

export type FileCategory =
  | "document"
  | "image"
  | "spreadsheet"
  | "presentation"
  | "archive"
  | "code"
  | "media"
  | "other";

export interface FileVersionItem {
  id: string;
  file_id: string;
  version_number: number;
  uploaded_by: string | null;
  size_bytes: number;
  encrypted_size_bytes: number;
  mime_type: string;
  sha256_checksum: string;
  is_encrypted: boolean;
  encryption_key_id: string | null;
  change_note: string | null;
  created_at: string;
}

export interface FileItem {
  id: string;
  owner_id: string;
  owner_name?: string | null;
  owner_email?: string | null;
  folder_id: string | null;
  name: string;
  original_name: string;
  extension: string;
  mime_type: string;
  category: FileCategory;
  description: string | null;
  tags: string[];
  size_bytes: number;
  encrypted_size_bytes: number;
  sha256_checksum: string;
  current_version: number;
  storage_backend: string;
  is_encrypted: boolean;
  encryption_key_id: string | null;
  download_count: number;
  is_starred: boolean;
  is_deleted: boolean;
  deleted_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface FileDetail extends FileItem {
  versions: FileVersionItem[];
}

export interface DashboardSummary {
  total_files: number;
  total_folders: number;
  encrypted_files: number;
  starred_files: number;
  trashed_files: number;
  total_versions: number;
  total_downloads: number;
  storage_used_bytes: number;
  storage_quota_bytes: number;
  storage_used_pct: number;
  categories: { category: string; count: number; size_bytes: number }[];
}

export interface AuditEvent {
  event_id: string;
  timestamp: string;
  actor_id: string | null;
  actor_email: string | null;
  actor_role: string | null;
  action: string;
  category: string;
  resource_type: string | null;
  resource_id: string | null;
  resource_name: string | null;
  status: "success" | "failure" | "blocked";
  severity: "info" | "warning" | "critical";
  ip_address: string | null;
  user_agent: string | null;
  request_id: string | null;
  details: Record<string, unknown>;
}

export interface DatastoreStatus {
  service: string;
  status: string;
  mode: string;
  engine?: string;
  latency_ms?: number;
  active_keys?: number;
  audit_documents?: number;
  stored_objects?: number;
  encryption?: string;
  max_upload_mb?: number;
  error?: string;
  role: string;
}
