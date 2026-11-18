
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime,
    ForeignKey, UniqueConstraint
)
from datetime import datetime
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="user")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Folder(Base):
    __tablename__ = "folders"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint(
            "name",
            "owner_id",
            name="unique_folder_per_user"
        ),
    )
    folder_id = Column(
    Integer,
    ForeignKey("folders.id"),
    nullable=True
    )


class FileModel(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Folder association; files can remain unorganized (NULL)
    folder_id = Column(
        Integer,
        ForeignKey("folders.id"),
        nullable=True
    )

    created_at = Column(DateTime, default=datetime.utcnow)

