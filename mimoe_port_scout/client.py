"""Thin HTTP client for mimOE's OpenAI-compatible chat completions endpoint.

Raw `requests` over the `openai` SDK: this is a single POST to one endpoint,
and writing it by hand keeps every request/response detail visible and easy
to explain, at the cost of the SDK's built-in retries/typed models (not
needed at this scale).
"""
import requests

from .config import Config

REQUEST_TIMEOUT_SECONDS = 30


class MimOEError(RuntimeError):
    """Base class for errors talking to mimOE."""


class MimOEConnectionError(MimOEError):
    """mimOE is not reachable (not running, wrong port, etc.)."""


class MimOETimeoutError(MimOEError):
    """mimOE didn't respond in time (model likely still loading, or hung)."""


class MimOEResponseError(MimOEError):
    """mimOE responded, but with an error status or unexpected body."""


def chat_completion(config: Config, messages: list[dict]) -> str:
    """Send a non-streaming chat completion request and return the reply text."""
    url = f"{config.base_url.rstrip('/')}/chat/completions"
    headers = {
        "Authorization": f"Bearer {config.api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": config.model,
        "messages": messages,
        "stream": False,
    }

    try:
        response = requests.post(
            url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT_SECONDS
        )
    except requests.exceptions.ConnectionError as exc:
        raise MimOEConnectionError(
            f"Could not connect to mimOE at {config.base_url}. "
            "Is mimOE Studio running?"
        ) from exc
    except requests.exceptions.Timeout as exc:
        raise MimOETimeoutError(
            f"mimOE did not respond within {REQUEST_TIMEOUT_SECONDS}s. "
            "The model may still be loading, or is stuck — check mimOE Studio."
        ) from exc

    if response.status_code == 404:
        raise MimOEResponseError(
            f"mimOE returned 404 for {url}. Check MIMOE_BASE_URL and that the "
            "model is loaded in mimOE Studio."
        )
    if response.status_code == 401:
        raise MimOEResponseError(
            "mimOE returned 401 Unauthorized. Check MIMOE_API_KEY."
        )
    if not response.ok:
        raise MimOEResponseError(
            f"mimOE returned HTTP {response.status_code}: {response.text[:500]}"
        )

    try:
        body = response.json()
        return body["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise MimOEResponseError(
            "mimOE returned a response that didn't match the expected "
            "OpenAI chat completion shape."
        ) from exc
