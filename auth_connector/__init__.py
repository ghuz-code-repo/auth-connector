"""
Auth Connector - Universal authentication and authorization module
for integrating services with the gateway auth-service.

Supports:
- Permission-based authorization
- User context extraction from headers
- Document requests from auth-service
- Permission validation and caching
- Service Discovery integration
- Easy integration with Flask, FastAPI, Django
"""

# 2.0.0 — ломающее: UserContext больше не имеет is_admin, декораторы потеряли
# параметр allow_admin. Права администратора приходят как '<service>.*'.
__version__ = "2.0.0"
__author__ = "Analytics Team"

from .auth_middleware import AuthMiddleware, require_permission, require_any_permission, get_current_user
from .auth_client import AuthClient
from .permissions import PermissionRegistry
from .permission_utils import any_permission_granted, extract_permissions, permission_granted
from .exceptions import AuthError, PermissionDeniedError, InvalidTokenError
from .service_discovery import ServiceDiscoveryClient, init_service_discovery_flask, init_service_discovery_fastapi

__all__ = [
    "AuthMiddleware",
    "AuthClient", 
    "PermissionRegistry",
    "require_permission",
    "require_any_permission",
    "get_current_user",
    "permission_granted",
    "any_permission_granted",
    "extract_permissions",
    "AuthError",
    "PermissionDeniedError", 
    "InvalidTokenError",
    "ServiceDiscoveryClient",
    "init_service_discovery_flask",
    "init_service_discovery_fastapi"
]