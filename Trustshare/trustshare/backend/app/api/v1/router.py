from fastapi import APIRouter

from app.api.v1 import auth, files, folders, health, users

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(folders.router)
api_router.include_router(files.router)
