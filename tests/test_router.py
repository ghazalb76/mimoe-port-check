from unittest.mock import patch

from mimoe_port_check.config import Config
from mimoe_port_check.router import keyword_fallback, route, strip_think_blocks

CONFIG = Config(
    base_url="http://localhost:8083/mimik-ai/openai/v1",
    model="smollm-360m",
    api_key="1234",
)


@patch("mimoe_port_check.router.chat_completion")
def test_route_uses_valid_model_json(mock_chat):
    mock_chat.return_value = '{"tool": "list_ports", "args": {}}'

    result = route("what's open?", CONFIG)

    assert result.tool == "list_ports"
    assert result.args == {}
    assert result.source == "model"


@patch("mimoe_port_check.router.chat_completion")
def test_route_extracts_json_surrounded_by_rambling(mock_chat):
    mock_chat.return_value = (
        "Sure! Here's what I think:\n"
        '{"tool": "check_exposure", "args": {"port": 5432}}\n'
        "Hope that helps!"
    )

    result = route("is 5432 exposed?", CONFIG)

    assert result.tool == "check_exposure"
    assert result.args == {"port": 5432}
    assert result.source == "model"


@patch("mimoe_port_check.router.chat_completion")
def test_route_coerces_quoted_numeric_args(mock_chat):
    mock_chat.return_value = '{"tool": "inspect_process", "args": {"pid": "512"}}'

    result = route("tell me about process 512", CONFIG)

    assert result.tool == "inspect_process"
    assert result.args == {"pid": 512}


@patch("mimoe_port_check.router.chat_completion")
def test_route_strips_think_block_before_parsing(mock_chat):
    mock_chat.return_value = (
        "<think>The user wants to know what's listening. I should use "
        'the {tool} format, e.g. {"example": "not real"}.</think>\n'
        '{"tool": "list_ports", "args": {}}'
    )

    result = route("what's open?", CONFIG)

    assert result.tool == "list_ports"
    assert result.args == {}
    assert result.source == "model"


@patch("mimoe_port_check.router.chat_completion")
def test_route_falls_back_when_only_a_think_block_is_present(mock_chat):
    # An unterminated/truncated think block (e.g. cut off by max_tokens)
    # leaves no real answer to find -- must fail safe to the fallback.
    mock_chat.return_value = "<think>Let me consider the options for this question"

    result = route("what's open?", CONFIG)

    assert result.source == "fallback"


@patch("mimoe_port_check.router.chat_completion")
def test_route_falls_back_on_garbage_output(mock_chat):
    mock_chat.return_value = "I like turtles."

    result = route("what's open on my machine?", CONFIG)

    assert result.source == "fallback"
    assert result.tool == "list_ports"


@patch("mimoe_port_check.router.chat_completion")
def test_route_falls_back_on_non_whitelisted_tool(mock_chat):
    mock_chat.return_value = '{"tool": "delete_everything", "args": {}}'

    result = route("what's open?", CONFIG)

    assert result.source == "fallback"


@patch("mimoe_port_check.router.chat_completion")
def test_route_falls_back_on_invalid_args_type(mock_chat):
    mock_chat.return_value = '{"tool": "inspect_process", "args": {"pid": "not-a-number"}}'

    result = route("tell me about process abc", CONFIG)

    assert result.source == "fallback"
    assert result.tool == "list_ports"  # no pid/port keyword in the question either


def test_strip_think_blocks_removes_complete_block():
    text = "<think>reasoning about the answer</think>The real answer."
    assert strip_think_blocks(text) == "The real answer."


def test_strip_think_blocks_leaves_text_without_one_alone():
    assert strip_think_blocks("just an answer") == "just an answer"


def test_keyword_fallback_detects_pid():
    result = keyword_fallback("what is process 512 doing?")
    assert result.tool == "inspect_process"
    assert result.args == {"pid": 512}
    assert result.source == "fallback"


def test_keyword_fallback_detects_port():
    result = keyword_fallback("what's on port 5432?")
    assert result.tool == "check_exposure"
    assert result.args == {"port": 5432}


def test_keyword_fallback_defaults_to_list_ports():
    result = keyword_fallback("is anything risky listening?")
    assert result.tool == "list_ports"
    assert result.args == {}


@patch("mimoe_port_check.router.chat_completion")
def test_route_debug_prints_raw_model_output(mock_chat, capsys):
    mock_chat.return_value = '{"tool": "list_ports", "args": {}}'

    route("what's open?", CONFIG, debug=True)

    captured = capsys.readouterr()
    assert "[debug]" in captured.out
    assert "list_ports" in captured.out


@patch("mimoe_port_check.router.chat_completion")
def test_route_without_debug_prints_nothing(mock_chat, capsys):
    mock_chat.return_value = '{"tool": "list_ports", "args": {}}'

    route("what's open?", CONFIG)

    captured = capsys.readouterr()
    assert captured.out == ""
