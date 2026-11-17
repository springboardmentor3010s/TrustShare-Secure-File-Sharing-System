"""Folder, EncryptionKey (envelope DEK), File, and FileVersion ORM models."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.postgres import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Folder(Base):
    __tablename__ = "folders"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    parent_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("folders.id", ondelete="CASCADE"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    color: Mapped[str] = mapped_column(String(24), nullable=False, default="indigo")
    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class EncryptionKey(Base):
    """
    Per-file-version Data Encryption Key (DEK) metadata for envelope encryption.
    Raw DEK bytes NEVER touch PostgreSQL; only AES-256-GCM wrapped ciphertext is stored.
    Key rotation (Milestone 2) simply unwraps with old KEK and re-wraps with new KEK
    without re-encrypting multi-gigabyte stored files.
    """

    __tablename__ = "encryption_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    kek_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, index=True)
    algorithm: Mapped[str] = mapped_column(String(40), nullable=False, default="AES-256-GCM-CHUNKED")
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrap_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    stream_base_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    chunk_size: Mapped[int] = mapped_column(Integer, nullable=False, default=65536)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="active")  # active|rotated|revoked
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class FileRecord(Base):
    __tablename__ = "files"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    folder_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("folders.id", ondelete="SET NULL"), nullable=True, index=True
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    original_name: Mapped[str] = mapped_column(String(255), nullable=False)
    extension: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    mime_type: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False, default="other", index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    encrypted_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256_checksum: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    storage_backend: Mapped[str] = mapped_column(String(24), nullable=False, default="local")
    storage_key: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)
    is_encrypted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    encryption_key_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("encryption_keys.id", ondelete="SET NULL"), nullable=True
    )

    download_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_starred: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    versions: Mapped[list["FileVersion"]] = relationship(
        back_populates="file",
        cascade="all, delete-orphan",
        order_by="desc(FileVersion.version_number)",
    )


class FileVersion(Base):
    __tablename__ = "file_versions"
    __table_args__ = (
        UniqueConstraint("file_id", "version_number", name="uq_file_version_num"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    file_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("files.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    uploaded_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    encrypted_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(128), nullable=False)
    sha256_checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    storage_backend: Mapped[str] = mapped_column(String(24), nullable=False, default="local")
    storage_key: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)
    is_encrypted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    encryption_key_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("encryption_keys.id", ondelete="SET NULL"), nullable=True
    )
    change_note: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    file: Mapped["FileRecord"] = relationship(back_populates="versions")
