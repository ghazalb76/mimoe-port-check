"""Configuration loading and the localhost-only safety guard.

System data (open ports, process names, command lines) is sensitive. This
agent must never send it to an inference endpoint that isn't running on the
local machine. The check below is a hard refusal with no override flag: if
you need to point at a remote endpoint, change the code deliberately.
"""
import os
from dataclasses import dataclass
from urllib.parse import urlparse

from dotenv import load_dotenv

DEFAULT_BASE_URL = "http://localhost:8083/mimik-ai/openai/v1"
DEFAULT_MODEL = "smollm-360m"
DEFAULT_API_KEY = "1234"

LOCALHOST_HOSTS = {"localhost", "127.0.0.1", "::1"}


class NonLocalEndpointError(RuntimeError):
    """Raised when the configured inference URL doesn't resolve to localhost."""


@dataclass(frozen=True)
class Config:
    base_url: str
    model: str
    api_key: str


def load_config() -> Config:
    load_dotenv()
    base_url = os.environ.get("MIMOE_BASE_URL", DEFAULT_BASE_URL)
    model = os.environ.get("MIMOE_MODEL", DEFAULT_MODEL)
    api_key = os.environ.get("MIMOE_API_KEY", DEFAULT_API_KEY)

    _assert_localhost(base_url)

    return Config(base_url=base_url, model=model, api_key=api_key)


def _assert_localhost(base_url: str) -> None:
    host = urlparse(base_url).hostname
    if host not in LOCALHOST_HOSTS:
        raise NonLocalEndpointError(
            f"Refusing to run: MIMOE_BASE_URL host is '{host}', not localhost.\n"
            "This agent inspects local system data (ports, processes) and must "
            "only send it to a model running on this machine. Point "
            "MIMOE_BASE_URL at a localhost address to proceed."
        )
