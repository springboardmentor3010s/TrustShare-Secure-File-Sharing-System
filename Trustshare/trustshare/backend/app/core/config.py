from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(str(BASE_DIR / ".env"), str(BASE_DIR.parent / ".env")),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Application
    APP_NAME: str = "TrustShare"
    APP_VERSION: str = "0.1.0-milestone1"
    APP_ENV: str = "development"
    API_V1_PREFIX: str = "/api/v1"
    CORS_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000"

    # PostgreSQL (Users, RBAC, File Metadata, Versions, Wrapped DEKs, Shares)
    DATABASE_URL: str = (
        "postgresql+psycopg://trustshare:trustshare_dev_pass@127.0.0.1:5432/trustshare"
    )

    # MongoDB (Immutable Audit Logs & Security Events)
    MONGODB_URI: str = "mongodb://127.0.0.1:27017"
    MONGODB_DB: str = "trustshare"
    MONGO_FALLBACK_DIR: str = str(BASE_DIR / "data" / "audit_store")

    # Redis (Sessions, JWT Denylist, Login Rate Limiting, MFA Challenges, Password Reset)
    REDIS_URL: str = "redis://127.0.0.1:6379/0"

    # JWT & Session Security
    JWT_SECRET_KEY: str = "change-me-in-prod-use-openssl-rand-hex-32-trustshare-m1"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    LOGIN_RATE_LIMIT_ATTEMPTS: int = 5
    LOGIN_RATE_LIMIT_WINDOW_SEC: int = 300
    MFA_CHALLENGE_TTL_SEC: int = 300
    PASSWORD_RESET_TTL_SEC: int = 900

    # Envelope Encryption (Server-Side AES-256-GCM: per-file DEK wrapped by KEK)
    # 32-byte dev key (base64 of b"TrustShareDevMasterKEK32Bytes991") — replace in prod / AWS KMS
    ENCRYPTION_ENABLED: bool = True
    MASTER_KEK_B64: str = "VHJ1c3RTaGFyZURldk1hc3RlcktFSzMyQnl0ZXM5OTE="
    MASTER_KEK_VERSION: int = 1
    ENCRYPTION_CHUNK_SIZE: int = 65536  # 64 KiB streaming AEAD chunks

    # Object Storage & Upload Security
    STORAGE_BACKEND: str = "local"  # local | s3 | azure (M2 cloud connectors)
    LOCAL_STORAGE_DIR: str = str(BASE_DIR / "data" / "encrypted_objects")
    MAX_UPLOAD_SIZE_MB: int = 50
    DEFAULT_USER_QUOTA_MB: int = 500
    BLOCKED_EXTENSIONS: str = (
        ".exe,.bat,.cmd,.com,.msi,.scr,.pif,.ps1,.vbs,.vbe,.jse,.wsf,.wsh,"
        ".elf,.dll,.so,.dylib,.app,.dmg,.php,.phtml,.jsp,.jspx,.asp,.aspx,.cgi,.hta"
    )

    # OAuth2 (Optional provider credentials)
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    OAUTH_REDIRECT_BASE_URL: str = "http://localhost:3000"

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def blocked_extensions_set(self) -> set[str]:
        return {e.strip().lower() for e in self.BLOCKED_EXTENSIONS.split(",") if e.strip()}

    @property
    def max_upload_bytes(self) -> int:
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    @property
    def default_quota_bytes(self) -> int:
        return self.DEFAULT_USER_QUOTA_MB * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    return Settings()
