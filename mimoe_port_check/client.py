"""Thin HTTP client for mimOE's OpenAI-compatible endpoints (chat
completions and, for model auto-selection, the models list).

Raw `requests` over the `openai` SDK: this is a couple of calls to one
local endpoint, and writing them by hand keeps every request/response
detail visible and easy to explain, at the cost of the SDK's built-in
retries/typed models (not needed at this scale).
"""
import dataclasses

import requests

from .config import Config

REQUEST_TIMEOUT_SECONDS = 30

# Preference order for model auto-selection (see select_model): the best
# routing accuracy/latency balance first, then the next-best tradeoff, with
# smollm-360m last since it ships with mimOE by default but its routing
# relies entirely on the keyword fallback (see NOTES.md / README "Model
# comparison" for the measurements behind this order).
MODEL_PREFERENCE = ["qwen3-1.7b", "qwen3-4b", "smollm-360m"]


class MimOEError(RuntimeError):
    """Base class for errors talking to mimOE."""


class MimOEConnectionError(MimOEError):
    """mimOE is not reachable (not running, wrong port, etc.)."""


class MimOETimeoutError(MimOEError):
    """mimOE didn't respond in time (model likely still loading, or hung)."""


class MimOEResponseError(MimOEError):
    """mimOE responded, but with an error status or unexpected body."""


class NoModelLoadedError(MimOEError):
    """None of MODEL_PREFERENCE is currently loaded in mimOE."""


def _send_request(request_fn, url: str, config: Config, **kwargs) -> requests.Response:
    """Issue a request with mimOE's connection-error/timeout handling,
    shared by chat_completion and list_models. request_fn is requests.post
    or requests.get -- kept as a direct call (not requests.request) so
    each caller's tests can patch the specific function they use."""
    headers = kwargs.pop("headers", {})
    headers.setdefault("Authorization", f"Bearer {config.api_key}")
    try:
        return request_fn(url, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS, **kwargs)
    except requests.exceptions.ConnectionError as exc:
        raise MimOEConnectionError(
            f"Could not connect to mimOE at {config.base_url}. "
            "Is mimOE Studio running?"
        ) from exc
    except requests.exceptions.Timeout as exc:
        raise MimOETimeoutError(
            f"mimOE did not respond within {REQUEST_TIMEOUT_SECONDS}s. "
            "The model may still be loading, or is stuck. Check mimOE Studio."
        ) from exc


def _raise_for_bad_status(response: requests.Response, url: str) -> None:
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


def chat_completion(
    config: Config,
    messages: list[dict],
    *,
    temperature: float = 0.2,
    max_tokens: int = 300,
) -> str:
    """Send a non-streaming chat completion request and return the reply text.

    Low temperature and a capped max_tokens keep this small model's output
    bounded: it doesn't reliably stop on its own, and left unconstrained it
    tends to drift into unrelated rambling (observed directly while building
    this: it sometimes hallucinates Python code instead of answering).
    """
    url = f"{config.base_url.rstrip('/')}/chat/completions"
    payload = {
        "model": config.model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": False,
    }

    response = _send_request(requests.post, url, config, json=payload)
    _raise_for_bad_status(response, url)

    try:
        body = response.json()
        return body["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise MimOEResponseError(
            "mimOE returned a response that didn't match the expected "
            "OpenAI chat completion shape."
        ) from exc


def list_models(config: Config) -> list[str]:
    """Return the IDs of models currently loaded in mimOE (GET .../models).
    config.model is irrelevant here -- this is used to *pick* config.model
    when it's not already set (see select_model)."""
    url = f"{config.base_url.rstrip('/')}/models"
    response = _send_request(requests.get, url, config)
    _raise_for_bad_status(response, url)

    try:
        body = response.json()
        return [entry["id"] for entry in body["data"]]
    except (ValueError, KeyError, TypeError) as exc:
        raise MimOEResponseError(
            "mimOE returned a response that didn't match the expected "
            "models-list shape."
        ) from exc


def select_model(config: Config) -> Config:
    """Auto-select a model from what's actually loaded in mimOE, in
    MODEL_PREFERENCE order, and return a Config with it filled in. Only
    meant to be called when config.model is None (MIMOE_MODEL wasn't set
    explicitly) -- see config.load_config."""
    available = set(list_models(config))
    for candidate in MODEL_PREFERENCE:
        if candidate in available:
            return dataclasses.replace(config, model=candidate)

    raise NoModelLoadedError(
        "No known model is loaded in mimOE (looked for: "
        f"{', '.join(MODEL_PREFERENCE)}). Load one of these in mimOE Studio, "
        "or set MIMOE_MODEL to use a different one."
    )
