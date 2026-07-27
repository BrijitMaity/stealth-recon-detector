import pytest
from auth import AuthManager


def test_auth_manager_initialization():
    am = AuthManager()
    assert "admin" in am.users


def test_successful_login():
    from config import cfg
    am = AuthManager()
    role = am.authenticate(cfg.DASHBOARD_USER, cfg.DASHBOARD_PASS)
    assert role == "admin"


def test_failed_login():
    am = AuthManager()
    role = am.authenticate("admin", "wrongpassword")
    assert role is None


def test_token_generation_and_validation():
    from config import cfg
    am = AuthManager()
    token = am.generate_token(cfg.DASHBOARD_USER, cfg.DASHBOARD_USER)
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
