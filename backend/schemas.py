
from pydantic import BaseModel, EmailStr
from typing import Literal


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    role: Literal["admin", "user"] = "user"


class UserResponse(BaseModel):
    id: int
    email: EmailStr
    role: str
    is_active: bool

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: str | None = None
    role: str | None = None
