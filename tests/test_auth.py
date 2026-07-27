import pytest
from auth import AuthManager


def test_auth_manager_initialization():
    am = AuthManager()
    assert "admin" in am.users


def test_successful_login():
    am = AuthManager()
    # Default RBAC_USERS includes admin:stealth2026:admin
    role = am.authenticate("admin", "stealth2026")
    assert role == "admin"


def test_failed_login():
    am = AuthManager()
    role = am.authenticate("admin", "wrongpassword")
    assert role is None


def test_token_generation_and_validation():
    am = AuthManager()
    token = am.generate_token("admin", "admin")
    assert token is not None

    payload = am.decode_token(token)
    assert isinstance(payload, dict)
    # JWT uses "sub" for subject, not "username"
    assert payload["sub"] == "admin"
    assert payload["role"] == "admin"


def test_invalid_token():
    am = AuthManager()
    payload = am.decode_token("invalid.token.string")
    # decode_token returns {"error": "..."} on failure, not None
    assert isinstance(payload, dict)
    assert "error" in payload
