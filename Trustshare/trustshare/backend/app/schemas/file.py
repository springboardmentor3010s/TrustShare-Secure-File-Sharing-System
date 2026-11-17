"""Pydantic schemas for Folders, Files, Versions, Dashboard Stats, and Audit Logs."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class FolderCreate(BaseModel):
    name: str = Field(min_length=1, max_length=180)
    parent_id: str | None = None
    color: str = Field(default="indigo", max_length=24)


class FolderUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=180)
    color: str | None = Field(default=None, max_length=24)


class FolderOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    owner_id: str
    parent_id: str | None
    name: str
    color: str
    file_count: int = 0
    created_at: datetime
    updated_at: datetime


class BreadcrumbItem(BaseModel):
    id: str
    name: str


class FileVersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    file_id: str
    version_number: int
    uploaded_by: str | None
    size_bytes: int
    encrypted_size_bytes: int
    mime_type: str
    sha256_checksum: str
    is_encrypted: bool
    encryption_key_id: str | None
    change_note: str | None
    created_at: datetime


class FileUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    folder_id: str | None = Field(default="__UNCHANGED__")
    category: str | None = Field(
        default=None,
        pattern="^(document|image|spreadsheet|presentation|archive|code|media|other)$",
    )
    description: str | None = Field(default=None, max_length=2000)
    tags: list[str] | None = None
    is_starred: bool | None = None


class FileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    owner_id: str
    owner_name: str | None = None
    owner_email: str | None = None
    folder_id: str | None
    name: str
    original_name: str
    extension: str
    mime_type: str
    category: str
    description: str | None
    tags: list[str]
    size_bytes: int
    encrypted_size_bytes: int
    sha256_checksum: str
    current_version: int
    storage_backend: str
    is_encrypted: bool
    encryption_key_id: str | None
    download_count: int
    is_starred: bool
    is_deleted: bool
    deleted_at: datetime | None
    created_at: datetime
    updated_at: datetime


class FileDetailOut(FileOut):
    versions: list[FileVersionOut] = []


class FileListResponse(BaseModel):
    items: list[FileOut]
    total: int
    page: int
    page_size: int


class CategoryBreakdown(BaseModel):
    category: str
    count: int
    size_bytes: int


class DashboardSummary(BaseModel):
    total_files: int
    total_folders: int
    encrypted_files: int
    starred_files: int
    trashed_files: int
    total_versions: int
    total_downloads: int
    storage_used_bytes: int
    storage_quota_bytes: int
    storage_used_pct: float
    categories: list[CategoryBreakdown]


class AuditLogListResponse(BaseModel):
    items: list[dict[str, Any]]
    total: int
    datastore_mode: str
