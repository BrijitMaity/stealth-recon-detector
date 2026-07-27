"""
auth.py — JWT Authentication and Role-Based Access Control (RBAC)

Features:
  - JWT token generation and validation
  - Role-based decorators for Flask routes
  - Graceful fallback to Basic Auth (for browsers)
  - Configurable expiry and secrets
"""

import jwt
import time
import pyotp
from functools import wraps
from flask import request, jsonify, Response
from config import cfg
from app_logger import get_logger

log = get_logger(__name__)


class AuthManager:
    def __init__(self):
        self.users = self._parse_users(cfg.RBAC_USERS)
        self.secret = cfg.JWT_SECRET
        self.algorithm = cfg.JWT_ALGORITHM
        self.expiry_hours = cfg.JWT_EXPIRY_HOURS

        # TOTP Setup
        import os
        self.totp_secret = os.environ.get("STEALTH_TOTP_SECRET")
        if not self.totp_secret:
            self.totp_secret = "JBSWY3DPEHPK3PXP"
            log.warning(f"STEALTH_TOTP_SECRET not set in environment. Using hardcoded fallback.")
        self.totp = pyotp.TOTP(self.totp_secret)
        uri = self.totp.provisioning_uri(name="admin@cyfocus", issuer_name="CyFocus SOC")

        log.info(f"AuthManager initialized with {len(self.users)} users. Roles: {[u['role'] for u in self.users.values()]}")
        
        # Print generated credentials for the user
        log.info(f"Admin Username: {cfg.DASHBOARD_USER}")
        log.info(f"Admin Password: {cfg.DASHBOARD_PASS}")
        log.info(f"TOTP 2FA Secret for Admin: {self.totp_secret}")
        log.info(f"TOTP 2FA Provisioning URI: {uri}")

    def _parse_users(self, users_str: str) -> dict:
        users = {}
        if not users_str:
            return users
        for user_entry in users_str.split(','):
            parts = user_entry.split(':')
            if len(parts) == 3:
                username, password, role = parts
                users[username.strip()] = {"password": password.strip(), "role": role.strip().lower()}
        return users

    def authenticate(self, username, password, totp_code=None):
        """Returns the role if authenticated, else None."""
        
        # 1. Verify against hardcoded dashboard user/pass first (Emergency Admin)
        if username == cfg.DASHBOARD_USER and password == cfg.DASHBOARD_PASS:
            if totp_code is not None and not self.totp.verify(totp_code):
                return None
            return "admin"
            
        # 2. Verify against database users
        from werkzeug.security import check_password_hash
        # To avoid circular imports, import state here
        from dashboard import state
        
        db_user = state.get_user(username)
        if db_user and check_password_hash(db_user["password_hash"], password):
            # Database users don't require TOTP in this configuration (as requested)
            return db_user["role"]

        return None

    def generate_token(self, username, role):
        payload = {
            "sub": username,
            "role": role,
            "iat": int(time.time()),
            "exp": int(time.time()) + (self.expiry_hours * 3600)
        }
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)

    def decode_token(self, token):
        try:
            return jwt.decode(token, self.secret, algorithms=[self.algorithm])
        except jwt.ExpiredSignatureError:
            return {"error": "Token expired"}
        except jwt.InvalidTokenError:
            return {"error": "Invalid token"}


auth_manager = AuthManager()


def requires_jwt(allowed_roles=None):
    """
    Decorator to protect routes. 
    Accepts JWT Bearer token or Basic Auth (for legacy/browser access).
    """
    if allowed_roles is None:
        allowed_roles = ["admin", "analyst", "viewer"]
        
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # 1. Check for Enterprise API Key (X-API-KEY)
            api_key = request.headers.get("X-API-KEY")
            # We load the API key directly from config. If blank, API keys are disabled.
            enterprise_key = getattr(cfg, "ENTERPRISE_API_KEY", "")
            if api_key and enterprise_key and api_key == enterprise_key:
                request.current_user = "api_client"
                request.current_role = "admin"
                return f(*args, **kwargs)

            # 2. Check for JWT Bearer token or Cookie
            token = None
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
            elif request.cookies.get("jwt_token"):
                token = request.cookies.get("jwt_token")

            if token:
                payload = auth_manager.decode_token(token)
                
                if "error" in payload:
                    # If it's a browser request (has cookie), don't return JSON 401, let it fall through or we can just return JSON for now
                    return jsonify({"error": payload["error"]}), 401
                    
                if payload.get("role") not in allowed_roles:
                    return jsonify({"error": f"Insufficient permissions. Requires one of: {allowed_roles}"}), 403
                    
                # Add user context to request
                request.current_user = payload.get("sub")
                request.current_role = payload.get("role")
                return f(*args, **kwargs)
            
            # 2. Check for Basic Auth
            auth = request.authorization
            if auth:
                role = auth_manager.authenticate(auth.username, auth.password)
                if role:
                    if role not in allowed_roles:
                        return jsonify({"error": f"Insufficient permissions. Requires one of: {allowed_roles}"}), 403
                        
                    request.current_user = auth.username
                    request.current_role = role
                    return f(*args, **kwargs)
            
            # 3. Fail
            return Response(
                'Authentication required. Please provide a Bearer token or valid Basic Auth credentials.\n', 401,
                {'WWW-Authenticate': 'Basic realm="AI Stealth Recon SOC"'}
            )
        return decorated
    return decorator
