from unittest.mock import patch

import pytest

from mimoe_port_check.config import NonLocalEndpointError, load_config

# load_config() calls load_dotenv(), which -- regardless of monkeypatch env
# changes -- anchors its search on config.py's own file location (not the
# cwd), so it will find and load this repo's real .env if one exists,
# undermining test isolation. Patch it out everywhere in this file so these
# tests only ever see the env vars they set themselves.
_patch_load_dotenv = patch("mimoe_port_check.config.load_dotenv")


def test_load_config_defaults(monkeypatch):
    monkeypatch.delenv("MIMOE_BASE_URL", raising=False)
    monkeypatch.delenv("MIMOE_MODEL", raising=False)
    monkeypatch.delenv("MIMOE_API_KEY", raising=False)

    with _patch_load_dotenv:
        config = load_config()

    assert config.base_url == "http://localhost:8083/mimik-ai/openai/v1"
    assert config.model is None  # unset -> caller auto-selects, see client.select_model
    assert config.api_key == "1234"


def test_load_config_reads_env(monkeypatch):
    monkeypatch.setenv("MIMOE_BASE_URL", "http://127.0.0.1:9999/v1")
    monkeypatch.setenv("MIMOE_MODEL", "some-model")
    monkeypatch.setenv("MIMOE_API_KEY", "secret")

    with _patch_load_dotenv:
        config = load_config()

    assert config.base_url == "http://127.0.0.1:9999/v1"
    assert config.model == "some-model"
    assert config.api_key == "secret"


def test_load_config_refuses_non_localhost(monkeypatch):
    monkeypatch.setenv("MIMOE_BASE_URL", "http://example.com/v1")

    with _patch_load_dotenv, pytest.raises(NonLocalEndpointError):
        load_config()
