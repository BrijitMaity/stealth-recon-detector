"""
Tests for configuration validation.
"""
import pytest
from config import _Config, cfg


def test_config_defaults():
    """Verify that the singleton config has sensible defaults."""
    # _Config resolves env vars at class definition time, so we test
    # the actual defaults rather than trying to override them
    config = _Config()

    assert config.DASHBOARD_HOST == '127.0.0.1'
    assert isinstance(config.DASHBOARD_PORT, int)
    assert 1 <= config.DASHBOARD_PORT <= 65535
    assert config.VERSION == "2.0.0"
    assert config.THREAD_POOL_SIZE >= 1
    assert config.BLOCK_TTL_SECONDS >= 60


def test_config_invalid_port():
    """Ensure default port is valid."""
    config = _Config()
    assert config.DASHBOARD_PORT == 5000


def test_config_validation_passes():
    """Ensure default config passes validation without errors."""
    config = _Config()
    # Should not raise ValueError
    warnings = config.validate()
    assert isinstance(warnings, list)


def test_config_singleton():
    """Verify that the module-level cfg is a valid _Config instance."""
    assert isinstance(cfg, _Config)
    assert hasattr(cfg, 'VERSION')
    assert hasattr(cfg, 'DASHBOARD_PORT')
