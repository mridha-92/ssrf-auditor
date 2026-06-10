"""Tests for configuration management."""

import pytest
import os
import tempfile
import yaml

from src.config import Config
from src.exceptions import ConfigurationError


class TestConfig:
    def test_defaults(self):
        config = Config()
        assert config.general["max_threads"] == 20
        assert config.rate_limiting["requests_per_second"] == 50
        assert config.module_enabled("ssrf_discovery") is True

    def test_custom_config(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({
                "general": {"max_threads": 50},
                "modules": {"ssrf_discovery": {"enabled": False}},
            }, f)
            f.flush()
            config_path = f.name

        try:
            config = Config(config_path)
            assert config.general["max_threads"] == 50
            assert config.module_enabled("ssrf_discovery") is False
            assert config.get("general.request_timeout") == 30
        finally:
            os.unlink(config_path)

    def test_missing_file(self):
        with pytest.raises(ConfigurationError):
            Config("nonexistent.yaml")

    def test_invalid_yaml(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("invalid: yaml: : broken")
            f.flush()
            config_path = f.name

        try:
            with pytest.raises(ConfigurationError):
                Config(config_path)
        finally:
            os.unlink(config_path)

    def test_get_set(self):
        config = Config()
        assert config.get("nonexistent.key", "default") == "default"
        config.set("custom.key", "value")
        assert config.get("custom.key") == "value"

    def test_module_config(self):
        config = Config()
        config._data["modules"]["test_module"] = {"enabled": True, "option": "val"}
        assert config.get("modules.test_module.option") == "val"
        assert config.module_enabled("test_module") is True
