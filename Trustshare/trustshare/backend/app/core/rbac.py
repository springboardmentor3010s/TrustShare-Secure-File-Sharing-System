"""
Role-Based Access Control (RBAC) model for TrustShare.

Four hierarchical roles map directly to the spec's user tiers
(Admins, Organization Managers, Standard Members, External Guests).
"""

from enum import StrEnum


class Role(StrEnum):
    ADMIN = "admin"
    MANAGER = "manager"
    MEMBER = "member"
    GUEST = "guest"


class Permission(StrEnum):
    # File & Folder operations
    FILE_READ = "file:read"
    FILE_DOWNLOAD = "file:download"
    FILE_UPLOAD = "file:upload"
    FILE_UPDATE = "file:update"
    FILE_VERSION = "file:version"
    FILE_DELETE = "file:delete"
    FILE_PURGE = "file:purge"
    FOLDER_MANAGE = "folder:manage"

    # Sharing (Milestone 2 enforcement hooks ready)
    SHARE_CREATE = "share:create"
    SHARE_REVOKE_ANY = "share:revoke_any"

    # Monitoring & Audit
    AUDIT_READ_OWN = "audit:read_own"
    AUDIT_READ_ALL = "audit:read_all"

    # Administration
    USER_READ_ALL = "user:read_all"
    USER_MANAGE_ROLES = "user:manage_roles"
    SYSTEM_HEALTH_DETAIL = "system:health_detail"


ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.GUEST: {
        Permission.FILE_READ,
        Permission.FILE_DOWNLOAD,
        Permission.AUDIT_READ_OWN,
    },
    Role.MEMBER: {
        Permission.FILE_READ,
        Permission.FILE_DOWNLOAD,
        Permission.FILE_UPLOAD,
        Permission.FILE_UPDATE,
        Permission.FILE_VERSION,
        Permission.FILE_DELETE,
        Permission.FOLDER_MANAGE,
        Permission.SHARE_CREATE,
        Permission.AUDIT_READ_OWN,
    },
    Role.MANAGER: {
        Permission.FILE_READ,
        Permission.FILE_DOWNLOAD,
        Permission.FILE_UPLOAD,
        Permission.FILE_UPDATE,
        Permission.FILE_VERSION,
        Permission.FILE_DELETE,
        Permission.FILE_PURGE,
        Permission.FOLDER_MANAGE,
        Permission.SHARE_CREATE,
        Permission.AUDIT_READ_OWN,
        Permission.AUDIT_READ_ALL,
        Permission.USER_READ_ALL,
        Permission.SYSTEM_HEALTH_DETAIL,
    },
    Role.ADMIN: set(Permission),  # Full permission set
}

ROLE_DEFAULT_QUOTA_MB: dict[Role, int] = {
    Role.GUEST: 0,
    Role.MEMBER: 500,
    Role.MANAGER: 2048,
    Role.ADMIN: 5120,
}


def get_permissions_for_role(role: str | Role) -> list[str]:
    try:
        r = Role(role)
    except ValueError:
        return []
    return sorted(p.value for p in ROLE_PERMISSIONS[r])


def has_permission(role: str | Role, permission: Permission) -> bool:
    try:
        r = Role(role)
    except ValueError:
        return False
    return permission in ROLE_PERMISSIONS[r]
