from unittest.mock import Mock, patch

import pytest
import requests

from mimoe_port_scout.client import (
    MimOEConnectionError,
    MimOEResponseError,
    MimOETimeoutError,
    chat_completion,
)
from mimoe_port_scout.config import Config

CONFIG = Config(
    base_url="http://localhost:8083/mimik-ai/openai/v1",
    model="smollm-360m",
    api_key="1234",
)


def _mock_response(status_code=200, json_body=None, text=""):
    resp = Mock()
    resp.status_code = status_code
    resp.ok = status_code < 400
    resp.text = text
    resp.json.return_value = json_body or {}
    return resp


@patch("mimoe_port_scout.client.requests.post")
def test_chat_completion_success(mock_post):
    mock_post.return_value = _mock_response(
        200,
        {"choices": [{"message": {"role": "assistant", "content": "hello there"}}]},
    )

    result = chat_completion(CONFIG, [{"role": "user", "content": "hi"}])

    assert result == "hello there"
    url = mock_post.call_args.args[0]
    assert url == "http://localhost:8083/mimik-ai/openai/v1/chat/completions"
    headers = mock_post.call_args.kwargs["headers"]
    assert headers["Authorization"] == "Bearer 1234"


@patch("mimoe_port_scout.client.requests.post")
def test_chat_completion_connection_error(mock_post):
    mock_post.side_effect = requests.exceptions.ConnectionError()

    with pytest.raises(MimOEConnectionError, match="Is mimOE Studio running"):
        chat_completion(CONFIG, [{"role": "user", "content": "hi"}])


@patch("mimoe_port_scout.client.requests.post")
def test_chat_completion_timeout(mock_post):
    mock_post.side_effect = requests.exceptions.Timeout()

    with pytest.raises(MimOETimeoutError):
        chat_completion(CONFIG, [{"role": "user", "content": "hi"}])


@patch("mimoe_port_scout.client.requests.post")
def test_chat_completion_404(mock_post):
    mock_post.return_value = _mock_response(404, text="not found")

    with pytest.raises(MimOEResponseError, match="404"):
        chat_completion(CONFIG, [{"role": "user", "content": "hi"}])


@patch("mimoe_port_scout.client.requests.post")
def test_chat_completion_401(mock_post):
    mock_post.return_value = _mock_response(401, text="unauthorized")

    with pytest.raises(MimOEResponseError, match="MIMOE_API_KEY"):
        chat_completion(CONFIG, [{"role": "user", "content": "hi"}])


@patch("mimoe_port_scout.client.requests.post")
def test_chat_completion_malformed_body(mock_post):
    mock_post.return_value = _mock_response(200, {"unexpected": "shape"})

    with pytest.raises(MimOEResponseError, match="expected"):
        chat_completion(CONFIG, [{"role": "user", "content": "hi"}])
