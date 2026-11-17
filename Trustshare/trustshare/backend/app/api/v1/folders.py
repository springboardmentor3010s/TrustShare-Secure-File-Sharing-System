"""Folder Management endpoints (nested folder hierarchy, breadcrumbs, rename, soft-delete)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.core.rbac import Permission
from app.db.postgres import get_db
from app.models.file import FileRecord, Folder
from app.models.user import User
from app.schemas.file import BreadcrumbItem, FolderCreate, FolderOut, FolderUpdate
from app.services.audit import log_audit_event

router = APIRouter(prefix="/folders", tags=["Folders"])

ALLOWED_COLORS = {"indigo", "emerald", "amber", "rose", "sky", "slate", "violet"}


def _to_folder_out(db: Session, folder: Folder) -> FolderOut:
    count = db.scalar(
        select(func.count(FileRecord.id)).where(
            FileRecord.folder_id == folder.id, FileRecord.is_deleted.is_(False)
        )
    ) or 0
    out = FolderOut.model_validate(folder)
    out.file_count = int(count)
    return out


@router.get("", response_model=list[FolderOut])
def list_folders(
    parent_id: str | None = Query(default=None),
    all_folders: bool = Query(default=False),
    user: User = Depends(require_permission(Permission.FILE_READ)),
    db: Session = Depends(get_db),
) -> list[FolderOut]:
    stmt = select(Folder).where(Folder.owner_id == user.id, Folder.is_deleted.is_(False))
    if not all_folders:
        if parent_id:
            stmt = stmt.where(Folder.parent_id == parent_id)
        else:
            stmt = stmt.where(Folder.parent_id.is_(None))
    stmt = stmt.order_by(Folder.name.asc())
    folders = db.scalars(stmt).all()
    return [_to_folder_out(db, f) for f in folders]


@router.post("", response_model=FolderOut, status_code=status.HTTP_201_CREATED)
def create_folder(
    payload: FolderCreate,
    request: Request,
    user: User = Depends(require_permission(Permission.FOLDER_MANAGE)),
    db: Session = Depends(get_db),
) -> FolderOut:
    clean_name = payload.name.strip().replace("/", "-").replace("\\", "-")
    if not clean_name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Folder name required.")

    if payload.parent_id:
        parent = db.get(Folder, payload.parent_id)
        if not parent or parent.owner_id != user.id or parent.is_deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parent folder not found.")

    dup = db.scalar(
        select(Folder).where(
            Folder.owner_id == user.id,
            Folder.parent_id == payload.parent_id,
            Folder.name == clean_name,
            Folder.is_deleted.is_(False),
        )
    )
    if dup:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A folder with that name already exists in this location.",
        )

    color = payload.color if payload.color in ALLOWED_COLORS else "indigo"
    folder = Folder(owner_id=user.id, parent_id=payload.parent_id, name=clean_name, color=color)
    db.add(folder)
    db.commit()
    db.refresh(folder)

    log_audit_event(
        action="folder.created",
        category="folder",
        actor=user,
        resource_type="folder",
        resource_id=folder.id,
        resource_name=folder.name,
        request=request,
        details={"parent_id": payload.parent_id},
    )
    return _to_folder_out(db, folder)


@router.get("/{folder_id}/breadcrumbs", response_model=list[BreadcrumbItem])
def folder_breadcrumbs(
    folder_id: str,
    user: User = Depends(require_permission(Permission.FILE_READ)),
    db: Session = Depends(get_db),
) -> list[BreadcrumbItem]:
    trail: list[BreadcrumbItem] = []
    cur = db.get(Folder, folder_id)
    if not cur or cur.owner_id != user.id or cur.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Folder not found.")

    safety = 0
    while cur is not None and safety < 20:
        trail.append(BreadcrumbItem(id=cur.id, name=cur.name))
        cur = db.get(Folder, cur.parent_id) if cur.parent_id else None
        safety += 1
    trail.reverse()
    return trail


@router.patch("/{folder_id}", response_model=FolderOut)
def update_folder(
    folder_id: str,
    payload: FolderUpdate,
    request: Request,
    user: User = Depends(require_permission(Permission.FOLDER_MANAGE)),
    db: Session = Depends(get_db),
) -> FolderOut:
    folder = db.get(Folder, folder_id)
    if not folder or folder.owner_id != user.id or folder.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Folder not found.")

    if payload.name is not None:
        clean = payload.name.strip().replace("/", "-").replace("\\", "-")
        if clean:
            folder.name = clean
    if payload.color is not None and payload.color in ALLOWED_COLORS:
        folder.color = payload.color

    db.commit()
    db.refresh(folder)

    log_audit_event(
        action="folder.updated",
        category="folder",
        actor=user,
        resource_type="folder",
        resource_id=folder.id,
        resource_name=folder.name,
        request=request,
    )
    return _to_folder_out(db, folder)


@router.delete("/{folder_id}")
def delete_folder(
    folder_id: str,
    request: Request,
    user: User = Depends(require_permission(Permission.FOLDER_MANAGE)),
    db: Session = Depends(get_db),
) -> dict:
    folder = db.get(Folder, folder_id)
    if not folder or folder.owner_id != user.id or folder.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Folder not found.")

    # Move direct child files back to parent folder so no user data is silently lost
    child_files = db.scalars(select(FileRecord).where(FileRecord.folder_id == folder.id)).all()
    for f in child_files:
        f.folder_id = folder.parent_id

    child_folders = db.scalars(select(Folder).where(Folder.parent_id == folder.id)).all()
    for cf in child_folders:
        cf.parent_id = folder.parent_id

    folder.is_deleted = True
    db.commit()

    log_audit_event(
        action="folder.deleted",
        category="folder",
        actor=user,
        resource_type="folder",
        resource_id=folder.id,
        resource_name=folder.name,
        request=request,
        details={"relocated_files": len(child_files)},
    )
    return {"message": "Folder deleted. Contained files relocated safely."}
