"""
Secure File Upload Validation & Streaming Envelope Encryption Service.

Defenses implemented:
1. Filename sanitization (Unicode NFC normalization, null-byte/control stripping,
   path traversal prevention, length cap, isolated UUID object storage keys).
2. Extension denylist enforcement (blocks executables, scripts, server-side webshells).
3. Magic-byte inspection (rejects PE/MZ, ELF, Mach-O, and disguised executables even
   when renamed to .pdf or .png).
4. Strict upload byte-limit and per-user storage quota checks while streaming (never
   buffers arbitrary giant uploads into RAM).
5. Streaming SHA-256 integrity hash over plaintext.
6. Streaming chunked AES-256-GCM envelope encryption (unique 256-bit DEK per uploaded
   version, wrapped under root KEK; per-chunk deterministic nonce + chunk-index/final-flag
   AAD prevents chunk reordering and truncation attacks; constant 64 KiB memory footprint).
"""

from __future__ import annotations

import hashlib
import mimetypes
import os
import re
import struct
import unicodedata
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import get_settings
from app.core.security import unwrap_key, wrap_key

# Magic-byte signatures of executable binaries that must NEVER be accepted, even if renamed
DANGEROUS_MAGIC_PREFIXES: list[tuple[bytes, str]] = [
    (b"MZ", "Windows PE/DOS executable (MZ header)"),
    (b"\x7fELF", "Linux/Unix ELF executable binary"),
    (b"\xfe\xed\xfa\xce", "macOS Mach-O 32-bit binary"),
    (b"\xfe\xed\xfa\xcf", "macOS Mach-O 64-bit binary"),
    (b"\xcf\xfa\xed\xfe", "macOS Mach-O 64-bit little-endian binary"),
    (b"\xca\xfe\xba\xbe", "Java class / Mach-O universal binary"),
    (b"<?php", "Server-side PHP script"),
]

CATEGORY_BY_EXT: dict[str, str] = {
    # Documents
    ".pdf": "document", ".doc": "document", ".docx": "document", ".txt": "document",
    ".md": "document", ".rtf": "document", ".odt": "document", ".tex": "document",
    # Spreadsheets
    ".xls": "spreadsheet", ".xlsx": "spreadsheet", ".csv": "spreadsheet",
    ".tsv": "spreadsheet", ".ods": "spreadsheet",
    # Presentations
    ".ppt": "presentation", ".pptx": "presentation", ".odp": "presentation", ".key": "presentation",
    # Images
    ".png": "image", ".jpg": "image", ".jpeg": "image", ".gif": "image",
    ".webp": "image", ".svg": "image", ".bmp": "image", ".ico": "image",
    # Archives
    ".zip": "archive", ".tar": "archive", ".gz": "archive", ".tgz": "archive",
    ".7z": "archive", ".rar": "archive", ".bz2": "archive",
    # Code & structured data
    ".py": "code", ".ts": "code", ".tsx": "code", ".jsx": "code", ".json": "code",
    ".yaml": "code", ".yml": "code", ".toml": "code", ".sql": "code", ".xml": "code",
    ".html": "code", ".css": "code", ".java": "code", ".go": "code", ".rs": "code",
    ".c": "code", ".cpp": "code", ".h": "code",
    # Media
    ".mp3": "media", ".wav": "media", ".ogg": "media", ".m4a": "media",
    ".mp4": "media", ".webm": "media", ".mov": "media", ".mkv": "media",
}

VALID_CATEGORIES = {
    "document", "image", "spreadsheet", "presentation", "archive", "code", "media", "other"
}

STREAM_MAGIC = b"TSENC01\x00"  # 8-byte file format header for TrustShare chunked AEAD blobs


class UploadValidationError(Exception):
    def __init__(self, message: str, reason_code: str = "validation_failed", status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.reason_code = reason_code
        self.status_code = status_code


@dataclass
class StoredBlobResult:
    sanitized_name: str
    extension: str
    mime_type: str
    inferred_category: str
    plaintext_size: int
    encrypted_size: int
    sha256_hex: str
    storage_backend: str
    storage_key: str
    is_encrypted: bool
    # Envelope DEK fields (populated when is_encrypted=True)
    kek_version: int | None = None
    wrapped_dek: bytes | None = None
    wrap_nonce: bytes | None = None
    stream_base_nonce: bytes | None = None
    chunk_size: int | None = None


def sanitize_filename(raw_filename: str | None) -> tuple[str, str]:
    """Strip directory paths, dangerous chars, and normalize Unicode. Returns (safe_name, lower_ext)."""
    if not raw_filename:
        raise UploadValidationError("Filename is required.", "missing_filename")

    # Normalize Unicode and drop any directory components (both POSIX / and Windows \)
    normalized = unicodedata.normalize("NFC", raw_filename)
    basename = normalized.replace("\\", "/").split("/")[-1].strip()
    # Remove null bytes and ASCII control characters
    basename = re.sub(r"[\x00-\x1f\x7f]", "", basename)
    # Replace unsafe filesystem characters while preserving readable names
    basename = re.sub(r'[<>:"|?*]', "_", basename)
    # Prevent hidden dotfiles like .htaccess or .env acting unexpectedly
    basename = basename.lstrip(".")

    if not basename:
        raise UploadValidationError("Filename contains no valid characters.", "invalid_filename")

    stem, ext = os.path.splitext(basename)
    ext_lower = ext.lower()[:24]
    safe_stem = (stem.strip() or "untitled")[:200]
    safe_name = f"{safe_stem}{ext_lower}"
    return safe_name, ext_lower


def validate_extension(filename: str, ext_lower: str) -> None:
    settings = get_settings()
    blocked = settings.blocked_extensions_set
    if ext_lower in blocked:
        raise UploadValidationError(
            f"File type '{ext_lower}' is blocked by security policy.",
            reason_code="blocked_extension",
            status_code=415,
        )
    # Also guard against dangerous double extensions like invoice.pdf.exe (covered above) or shell.php.jpg
    parts = [f".{p.lower()}" for p in filename.split(".")[1:]]
    for part in parts:
        if part in {".exe", ".bat", ".cmd", ".ps1", ".php", ".phtml", ".jsp", ".asp", ".aspx"}:
            raise UploadValidationError(
                f"Suspicious double extension '{part}' blocked by security policy.",
                reason_code="double_extension",
                status_code=415,
            )


def inspect_magic_bytes(header: bytes, declared_ext: str) -> None:
    for sig, label in DANGEROUS_MAGIC_PREFIXES:
        if header.startswith(sig):
            raise UploadValidationError(
                f"Upload blocked: file header matches {label}.",
                reason_code="malicious_magic_bytes",
                status_code=415,
            )
    # Block disguised shell scripts with #! shebang unless explicitly a plain text note is NOT executable
    if header.startswith(b"#!") and declared_ext in {".pdf", ".png", ".jpg", ".jpeg", ".docx", ".xlsx", ".zip"}:
        raise UploadValidationError(
            "Upload blocked: executable script header disguised inside document/image extension.",
            reason_code="mime_spoofing",
            status_code=415,
        )
    # If claiming to be a PDF, verify %PDF- signature
    if declared_ext == ".pdf" and len(header) >= 5 and not header.startswith(b"%PDF-"):
        raise UploadValidationError(
            "Upload blocked: '.pdf' file does not contain a valid %PDF header (possible MIME spoofing).",
            reason_code="pdf_header_mismatch",
            status_code=415,
        )
    # If claiming to be a PNG, verify PNG 8-byte signature
    if declared_ext == ".png" and len(header) >= 8 and not header.startswith(b"\x89PNG\r\n\x1a\n"):
        raise UploadValidationError(
            "Upload blocked: '.png' file does not contain a valid PNG signature (possible MIME spoofing).",
            reason_code="png_header_mismatch",
            status_code=415,
        )


def resolve_mime_and_category(
    safe_name: str, ext_lower: str, client_content_type: str | None, override_category: str | None
) -> tuple[str, str]:
    guessed, _ = mimetypes.guess_type(safe_name)
    mime = guessed or (client_content_type if client_content_type and "/" in client_content_type else None) or "application/octet-stream"
    if override_category and override_category in VALID_CATEGORIES:
        category = override_category
    else:
        category = CATEGORY_BY_EXT.get(ext_lower, "other")
    return mime[:128], category


def _derive_chunk_nonce(base_nonce: bytes, chunk_index: int) -> bytes:
    """XOR the last 8 bytes of a 12-byte random base nonce with big-endian chunk index (RFC 8446 style)."""
    prefix = base_nonce[:4]
    tail_int = struct.unpack(">Q", base_nonce[4:])[0] ^ chunk_index
    return prefix + struct.pack(">Q", tail_int)


def _chunk_aad(chunk_index: int, is_final: bool) -> bytes:
    return b"ts-chunk-v1:" + struct.pack(">QB", chunk_index, 1 if is_final else 0)


def _resolve_local_path(storage_key: str) -> Path:
    settings = get_settings()
    root = Path(settings.LOCAL_STORAGE_DIR).resolve()
    root.mkdir(parents=True, exist_ok=True)
    target = (root / storage_key).resolve()
    if root not in target.parents:
        raise ValueError("Invalid storage key path traversal attempt.")
    target.parent.mkdir(parents=True, exist_ok=True)
    return target


def store_uploaded_stream(
    *,
    stream: BinaryIO,
    raw_filename: str | None,
    client_content_type: str | None,
    owner_id: str,
    remaining_quota_bytes: int,
    override_category: str | None = None,
) -> StoredBlobResult:
    """
    Validate, hash, encrypt (chunked AES-256-GCM with fresh per-file DEK), and persist an upload stream.
    Cleans up any partial blob automatically if validation or quota fails mid-stream.
    """
    settings = get_settings()
    safe_name, ext_lower = sanitize_filename(raw_filename)
    validate_extension(safe_name, ext_lower)
    mime_type, category = resolve_mime_and_category(
        safe_name, ext_lower, client_content_type, override_category
    )

    chunk_size = settings.ENCRYPTION_CHUNK_SIZE
    max_bytes = settings.max_upload_bytes
    encrypt = settings.ENCRYPTION_ENABLED

    # Isolated non-guessable object path partitioned by owner prefix
    obj_uuid = uuid.uuid4().hex
    suffix = ".enc" if encrypt else ".bin"
    storage_key = f"{owner_id[:8]}/{obj_uuid[:2]}/{obj_uuid}{suffix}"
    dest_path = _resolve_local_path(storage_key)

    hasher = hashlib.sha256()
    plaintext_size = 0
    encrypted_size = 0

    dek: bytes | None = None
    aead: AESGCM | None = None
    base_nonce: bytes | None = None
    wrapped_dek: bytes | None = None
    wrap_nonce: bytes | None = None

    if encrypt:
        dek = os.urandom(32)  # Fresh 256-bit AES key unique to this file version
        wrapped_dek, wrap_nonce = wrap_key(dek)
        base_nonce = os.urandom(12)
        aead = AESGCM(dek)

    try:
        first_chunk = stream.read(chunk_size)
        if not first_chunk:
            raise UploadValidationError("Cannot upload an empty (0-byte) file.", "empty_file", 400)

        inspect_magic_bytes(first_chunk[:64], ext_lower)

        with dest_path.open("wb") as out:
            if encrypt:
                out.write(STREAM_MAGIC)
                encrypted_size += len(STREAM_MAGIC)

            chunk_index = 0
            current = first_chunk
            while True:
                next_chunk = stream.read(chunk_size)
                is_final = len(next_chunk) == 0

                plaintext_size += len(current)
                if plaintext_size > max_bytes:
                    raise UploadValidationError(
                        f"File exceeds maximum allowed upload size of {settings.MAX_UPLOAD_SIZE_MB} MB.",
                        reason_code="file_too_large",
                        status_code=413,
                    )
                if plaintext_size > remaining_quota_bytes:
                    raise UploadValidationError(
                        "Insufficient storage quota remaining for this upload.",
                        reason_code="quota_exceeded",
                        status_code=413,
                    )

                hasher.update(current)

                if encrypt and aead is not None and base_nonce is not None:
                    nonce = _derive_chunk_nonce(base_nonce, chunk_index)
                    aad = _chunk_aad(chunk_index, is_final)
                    ct = aead.encrypt(nonce, current, aad)
                    frame_header = struct.pack(">IB", len(ct), 1 if is_final else 0)
                    out.write(frame_header)
                    out.write(ct)
                    encrypted_size += len(frame_header) + len(ct)
                else:
                    out.write(current)
                    encrypted_size += len(current)

                if is_final:
                    break
                current = next_chunk
                chunk_index += 1

    except Exception:
        if dest_path.exists():
            dest_path.unlink(missing_ok=True)
        raise
    finally:
        # Clear reference to raw DEK immediately after encryption completes
        dek = None

    return StoredBlobResult(
        sanitized_name=safe_name,
        extension=ext_lower,
        mime_type=mime_type,
        inferred_category=category,
        plaintext_size=plaintext_size,
        encrypted_size=encrypted_size,
        sha256_hex=hasher.hexdigest(),
        storage_backend=settings.STORAGE_BACKEND,
        storage_key=storage_key,
        is_encrypted=encrypt,
        kek_version=settings.MASTER_KEK_VERSION if encrypt else None,
        wrapped_dek=wrapped_dek,
        wrap_nonce=wrap_nonce,
        stream_base_nonce=base_nonce,
        chunk_size=chunk_size if encrypt else None,
    )


def stream_decrypted_blob(
    *,
    storage_key: str,
    is_encrypted: bool,
    wrapped_dek: bytes | None = None,
    wrap_nonce: bytes | None = None,
    stream_base_nonce: bytes | None = None,
) -> Iterator[bytes]:
    """
    Yields authenticated, decrypted plaintext chunks directly in memory without ever writing
    decrypted bytes to disk. Raises InvalidTag if any byte, order, or length was tampered with.
    """
    src_path = _resolve_local_path(storage_key)
    if not src_path.exists():
        raise FileNotFoundError(f"Stored object not found: {storage_key}")

    if not is_encrypted:
        with src_path.open("rb") as fh:
            while chunk := fh.read(65536):
                yield chunk
        return

    if not (wrapped_dek and wrap_nonce and stream_base_nonce):
        raise ValueError("Missing envelope key material for encrypted file.")

    dek = unwrap_key(wrapped_dek, wrap_nonce)
    aead = AESGCM(dek)
    del dek

    with src_path.open("rb") as fh:
        magic = fh.read(len(STREAM_MAGIC))
        if magic != STREAM_MAGIC:
            raise ValueError("Corrupted encrypted object header.")

        chunk_index = 0
        saw_final = False
        while True:
            hdr = fh.read(5)
            if not hdr:
                break
            if len(hdr) != 5:
                raise ValueError("Truncated encrypted frame header.")
            ct_len, final_flag = struct.unpack(">IB", hdr)
            is_final = final_flag == 1
            ct = fh.read(ct_len)
            if len(ct) != ct_len:
                raise ValueError("Truncated encrypted frame payload.")
            nonce = _derive_chunk_nonce(stream_base_nonce, chunk_index)
            aad = _chunk_aad(chunk_index, is_final)
            plaintext = aead.decrypt(nonce, ct, aad)
            yield plaintext
            chunk_index += 1
            if is_final:
                saw_final = True
                break

        if not saw_final:
            raise ValueError("Encrypted stream truncated before final authenticated chunk.")


def delete_stored_blob(storage_key: str) -> None:
    try:
        path = _resolve_local_path(storage_key)
        path.unlink(missing_ok=True)
    except Exception:
        pass
