
from fastapi import APIRouter, Depends, HTTPException, Header, Form, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import jwt, JWTError

from database import SessionLocal
from models import User
from schemas import UserCreate, UserResponse, Token
from security import (
    hash_password,
    verify_password,
    create_access_token,
    SECRET_KEY,
    ALGORITHM
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        email = payload.get("sub")

        if email is None:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.email == email).first()

    if user is None or not user.is_active:
        raise credentials_exception

    return user


def require_role(*allowed_roles: str):
    def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this resource"
            )
        return current_user

    return role_checker


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED
)
def register(
    user_data: UserCreate,
    db: Session = Depends(get_db)
):
    if user_data.role == "admin":
        existing_admin = db.query(User).filter(User.role == "admin").first()
        if existing_admin is not None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="An admin account already exists. Select User or contact the administrator."
            )

    existing_user = db.query(User).filter(
        User.email == user_data.email
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    new_user = User(
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
        role=user_data.role
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@router.post("/login", response_model=Token)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    role: str = Form(default=""),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(
        User.email == form_data.username
    ).first()

    if (
        not user
        or not user.is_active
        or not verify_password(form_data.password, user.hashed_password)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if role and role != user.role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Selected role does not match this account"
        )

    access_token = create_access_token(
        data={
            "sub": user.email,
            "role": user.role
        }
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


@router.get("/me", response_model=UserResponse)
def get_my_profile(
    current_user: User = Depends(get_current_user)
):
    return current_user


@router.post(
    "/create-admin",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED
)
def create_admin_user(
    user_data: UserCreate,
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None, alias="Authorization")
):
    existing_admin = db.query(User).filter(User.role == "admin").first()

    if existing_admin is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only one admin account is allowed in this system"
        )

    if authorization:
        token = authorization.replace("Bearer ", "", 1).strip()
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            email = payload.get("sub")
            if email is None:
                raise JWTError()
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"}
            )

    existing_user = db.query(User).filter(
        User.email == user_data.email
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    new_user = User(
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
        role="admin",
        is_active=True
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@router.get("/users")
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin"))
):
    users = db.query(User).order_by(User.created_at.desc()).all()

    return [
        {
            "id": user.id,
            "email": user.email,
            "role": user.role,
            "is_active": user.is_active,
            "created_at": user.created_at
        }
        for user in users
    ]


@router.get("/admin-only")
def admin_only(
    current_user: User = Depends(require_role("admin"))
):
    return {
        "message": "Welcome Admin",
        "email": current_user.email
    }


@router.get("/user-only")
def user_only(
    current_user: User = Depends(require_role("user"))
):
    return {
        "message": "Welcome User",
        "email": current_user.email
    }
