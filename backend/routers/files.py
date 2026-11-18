
from fastapi import (
    APIRouter, Depends, UploadFile, File,
    HTTPException, status
)
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime
import os
import uuid

from database import SessionLocal, audit_collection
from models import User, FileModel, Folder
from routers.auth import get_current_user, require_role

router = APIRouter(prefix="/files", tags=["File Management"])

UPLOAD_DIR = os.path.abspath("uploaded_files")
MAX_FILE_SIZE = 25 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024

os.makedirs(UPLOAD_DIR, exist_ok=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------
# CREATE FOLDER
# ---------------------------------

@router.post("/folders", status_code=status.HTTP_201_CREATED)
def create_folder(
    name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    name = name.strip()

    if not name or len(name) > 100:
        raise HTTPException(
            status_code=400,
            detail="Folder name must contain 1 to 100 characters"
        )

    existing_folder = db.query(Folder).filter(
        Folder.name == name,
        Folder.owner_id == current_user.id
    ).first()

    if existing_folder:
        raise HTTPException(
            status_code=409,
            detail="Folder already exists"
        )

    folder = Folder(
        name=name,
        owner_id=current_user.id
    )

    try:
        db.add(folder)
        db.commit()
        db.refresh(folder)
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Could not create folder"
        )

    return {
        "message": "Folder created successfully",
        "folder_id": folder.id,
        "name": folder.name
    }


# ---------------------------------
# GET USER FOLDERS
# ---------------------------------

@router.get("/folders")
def get_my_folders(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    folders = db.query(Folder).filter(
        Folder.owner_id == current_user.id
    ).order_by(Folder.created_at.desc()).all()

    return [
        {
            "folder_id": folder.id,
            "name": folder.name,
            "created_at": folder.created_at
        }
        for folder in folders
    ]


# ---------------------------------
# UPLOAD FILE
# ---------------------------------

@router.post("/upload", status_code=status.HTTP_201_CREATED)
def upload_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="Filename is required"
        )

    original_filename = os.path.basename(
        file.filename.replace("\\", "/")
    )

    if not original_filename or original_filename in (".", ".."):
        raise HTTPException(
            status_code=400,
            detail="Invalid filename"
        )

    stored_filename = f"{uuid.uuid4().hex}_{original_filename}"
    file_path = os.path.join(UPLOAD_DIR, stored_filename)

    total_size = 0

    try:
        with open(file_path, "wb") as buffer:
            while True:
                chunk = file.file.read(CHUNK_SIZE)

                if not chunk:
                    break

                total_size += len(chunk)

                if total_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="File size exceeds the 25 MB limit"
                    )

                buffer.write(chunk)

        if total_size == 0:
            raise HTTPException(
                status_code=400,
                detail="Empty files are not allowed"
            )

        db_file = FileModel(
            filename=original_filename,
            file_path=file_path,
            owner_id=current_user.id,
            folder_id=None
        )

        db.add(db_file)
        db.commit()
        db.refresh(db_file)

    except HTTPException:
        if os.path.exists(file_path):
            os.remove(file_path)
        raise

    except (OSError, SQLAlchemyError):
        db.rollback()

        if os.path.exists(file_path):
            os.remove(file_path)

        raise HTTPException(
            status_code=500,
            detail="File upload failed"
        )

    finally:
        file.file.close()

    try:
        audit_collection.insert_one({
            "user_email": current_user.email,
            "action": "FILE_UPLOAD",
            "file_id": db_file.id,
            "filename": original_filename,
            "timestamp": datetime.utcnow()
        })
    except Exception:
        pass

    return {
        "message": "File uploaded successfully",
        "file_id": db_file.id,
        "filename": db_file.filename,
        "size_bytes": total_size,
        "owner_id": current_user.id,
        "folder_id": db_file.folder_id
    }


# ---------------------------------
# GET USER FILES
# ---------------------------------

@router.get("/my-files")
def get_my_files(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    files = db.query(FileModel).filter(
        FileModel.owner_id == current_user.id
    ).all()

    return [
        {
            "file_id": item.id,
            "filename": item.filename,
            "folder_id": item.folder_id,
            "created_at": item.created_at
        }
        for item in files
    ]


@router.get("/admin/all-files")
def get_all_files_admin(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin"))
):
    files = db.query(FileModel).order_by(FileModel.created_at.desc()).all()

    return [
        {
            "file_id": item.id,
            "filename": item.filename,
            "owner_id": item.owner_id,
            "folder_id": item.folder_id,
            "created_at": item.created_at
        }
        for item in files
    ]


# ---------------------------------
# MOVE FILE INTO FOLDER
# ---------------------------------

@router.patch("/{file_id}/move/{folder_id}")
def move_file(
    file_id: int,
    folder_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    db_file = db.query(FileModel).filter(
        FileModel.id == file_id,
        FileModel.owner_id == current_user.id
    ).first()

    if not db_file:
        raise HTTPException(
            status_code=404,
            detail="File not found"
        )

    folder = db.query(Folder).filter(
        Folder.id == folder_id,
        Folder.owner_id == current_user.id
    ).first()

    if not folder:
        raise HTTPException(
            status_code=404,
            detail="Folder not found"
        )

    db_file.folder_id = folder.id

    try:
        db.commit()
        db.refresh(db_file)
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Could not move file"
        )

    try:
        audit_collection.insert_one({
            "user_email": current_user.email,
            "action": "FILE_MOVED",
            "file_id": db_file.id,
            "folder_id": folder.id,
            "timestamp": datetime.utcnow()
        })
    except Exception:
        pass

    return {
        "message": "File moved successfully",
        "file_id": db_file.id,
        "folder_id": folder.id
    }


# ---------------------------------
# VIEW FILES INSIDE A FOLDER
# ---------------------------------

@router.get("/folders/{folder_id}/files")
def get_folder_files(
    folder_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    folder = db.query(Folder).filter(
        Folder.id == folder_id,
        Folder.owner_id == current_user.id
    ).first()

    if not folder:
        raise HTTPException(
            status_code=404,
            detail="Folder not found"
        )

    files = db.query(FileModel).filter(
        FileModel.folder_id == folder_id,
        FileModel.owner_id == current_user.id
    ).all()

    return [
        {
            "file_id": item.id,
            "filename": item.filename,
            "folder_id": item.folder_id,
            "created_at": item.created_at
        }
        for item in files
    ]
