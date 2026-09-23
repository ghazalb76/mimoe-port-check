import pytest

from mimoe_port_scout.config import NonLocalEndpointError, load_config


def test_load_config_defaults(monkeypatch):
    monkeypatch.delenv("MIMOE_BASE_URL", raising=False)
    monkeypatch.delenv("MIMOE_MODEL", raising=False)
    monkeypatch.delenv("MIMOE_API_KEY", raising=False)

    config = load_config()

    assert config.base_url == "http://localhost:8083/mimik-ai/openai/v1"
    assert config.model == "smollm-360m"
    assert config.api_key == "1234"


def test_load_config_reads_env(monkeypatch):
    monkeypatch.setenv("MIMOE_BASE_URL", "http://127.0.0.1:9999/v1")
    monkeypatch.setenv("MIMOE_MODEL", "some-model")
    monkeypatch.setenv("MIMOE_API_KEY", "secret")

    config = load_config()

    assert config.base_url == "http://127.0.0.1:9999/v1"
    assert config.model == "some-model"
    assert config.api_key == "secret"


def test_load_config_refuses_non_localhost(monkeypatch):
    monkeypatch.setenv("MIMOE_BASE_URL", "http://example.com/v1")

    with pytest.raises(NonLocalEndpointError):
        load_config()
