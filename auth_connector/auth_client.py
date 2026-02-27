"""
Auth client for communicating with auth-service
"""

import os
import requests
import json
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging
from .exceptions import AuthServiceUnavailableError, InvalidTokenError

logger = logging.getLogger(__name__)


class AuthClient:
    """Client for auth-service communication"""
    
    def __init__(self, auth_service_url: str, service_key: str, timeout: int = 10,
                 api_key: str = None):
        self.auth_service_url = auth_service_url.rstrip('/')
        self.service_key = service_key
        self.timeout = timeout
        self._api_key = api_key or os.getenv('INTERNAL_API_KEY', '')
        self._cache = {}
        self._cache_ttl = {}
        
        # Session with default X-API-Key header for all requests
        self._session = requests.Session()
        if self._api_key:
            self._session.headers['X-API-Key'] = self._api_key
    
    @property
    def api_headers(self) -> Dict[str, str]:
        """Return headers dict with X-API-Key for use in direct requests.get() calls.
        
        Usage in services that make direct HTTP calls to auth-service /api/* endpoints:
            response = requests.get(url, headers=auth_client.api_headers, timeout=5)
        """
        if self._api_key:
            return {'X-API-Key': self._api_key}
        return {}
    
    def get_user_permissions(self, user_id: str, force_refresh: bool = False) -> List[str]:
        """Get user permissions for this service.
        
        DEPRECATED: This method calls /api/users/{id}/permissions/{service_key}
        which does not exist in auth-service. Permissions should be obtained from
        nginx gateway headers (X-User-Service-Permissions) instead.
        Kept for API compatibility — will log a warning if called.
        """
        import warnings
        warnings.warn(
            "AuthClient.get_user_permissions() is deprecated. "
            "Use X-User-Service-Permissions header from nginx gateway instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        logger.warning(
            "DEPRECATED: get_user_permissions() called for user=%s service=%s. "
            "This endpoint does not exist in auth-service. "
            "Use X-User-Service-Permissions header instead.",
            user_id, self.service_key,
        )
        cache_key = f"permissions:{user_id}"
        
        # Check cache first
        if not force_refresh and self._is_cached(cache_key):
            return self._cache[cache_key]
        
        try:
            url = f"{self.auth_service_url}/api/users/{user_id}/permissions/{self.service_key}"
            response = self._session.get(url, timeout=self.timeout)
            
            if response.status_code == 404:
                return []  # User has no permissions for this service
            
            response.raise_for_status()
            data = response.json()
            permissions = data.get('permissions', [])
            
            # Cache for 5 minutes
            self._cache[cache_key] = permissions
            self._cache_ttl[cache_key] = datetime.now() + timedelta(minutes=5)
            
            return permissions
            
        except requests.RequestException as e:
            logger.error(f"Failed to get user permissions: {e}")
            # Return cached data if available, otherwise empty list
            return self._cache.get(cache_key, [])
    
    def get_user_document(self, user_id: str, document_type: str = None) -> Optional[Dict[str, Any]]:
        """Get user document from auth-service"""
        try:
            url = f"{self.auth_service_url}/api/users/{user_id}/documents"
            params = {"type": document_type} if document_type else {}
            
            response = self._session.get(url, params=params, timeout=self.timeout)
            
            if response.status_code == 404:
                return None
            
            response.raise_for_status()
            return response.json()
            
        except requests.RequestException as e:
            logger.error(f"Failed to get user document: {e}")
            return None
    
    def validate_token(self, token: str) -> Dict[str, Any]:
        """Validate auth token and get user info"""
        try:
            url = f"{self.auth_service_url}/api/validate-token"
            headers = {"Authorization": f"Bearer {token}"}
            
            response = self._session.post(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 401:
                raise InvalidTokenError("Token is invalid or expired")
            
            response.raise_for_status()
            return response.json()
            
        except requests.RequestException as e:
            logger.error(f"Failed to validate token: {e}")
            raise AuthServiceUnavailableError(f"Auth service unavailable: {e}")
    
    def sync_permissions(self, permissions: List[Dict[str, str]]) -> bool:
        """Sync service permissions with auth-service"""
        try:
            url = f"{self.auth_service_url}/api/services/{self.service_key}/permissions/sync"
            payload = {
                "service_key": self.service_key,
                "permissions": permissions
            }
            
            response = self._session.post(url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            
            logger.info(f"Successfully synced {len(permissions)} permissions for service {self.service_key}")
            return True
            
        except requests.RequestException as e:
            logger.error(f"Failed to sync permissions: {e}")
            return False
    
    def health_check(self) -> bool:
        """Check if auth-service is available"""
        try:
            url = f"{self.auth_service_url}/health"
            response = self._session.get(url, timeout=self.timeout)
            return response.status_code == 200
        except:
            return False
    
    def _is_cached(self, key: str) -> bool:
        """Check if data is cached and not expired"""
        if key not in self._cache:
            return False
        if key not in self._cache_ttl:
            return False
        return datetime.now() < self._cache_ttl[key]
    
    def clear_cache(self):
        """Clear all cached data"""
        self._cache.clear()
        self._cache_ttl.clear()