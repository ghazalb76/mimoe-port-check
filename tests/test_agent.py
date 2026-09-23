from unittest.mock import patch

from mimoe_port_check.agent import (
    INVALID_PID_TOOL,
    OFF_TOPIC_TOOL,
    _print_welcome,
    deterministic_explanation,
    find_exposure_contradiction,
    find_ungrounded_claims,
    format_check_exposure,
    format_inspect_process,
    format_list_ports,
    has_nothing_to_explain,
    is_on_topic,
    resolve_route,
    run_tool,
    summarize_notable,
    trim_to_complete_sentence,
)
from mimoe_port_check.config import Config
from mimoe_port_check.router import Route
from mimoe_port_check.tools import ExposureReport, PortEntry, ProcessDetails

CONFIG = Config(
    base_url="http://localhost:8083/mimik-ai/openai/v1",
    model="smollm-360m",
    api_key="1234",
)


def test_format_list_ports_empty():
    assert format_list_ports([]) == "No listening TCP ports found."


def test_format_list_ports_includes_key_fields():
    entry = PortEntry(
        port=5432,
        protocol="tcp",
        local_address="127.0.0.1",
        pid=222,
        command="postgres",
        exposed_to_network=False,
        service_name="PostgreSQL",
        risk="LOW",
        risk_note="Bound to localhost only.",
    )

    text = format_list_ports([entry])

    assert "5432" in text
    assert "PostgreSQL" in text
    assert "LOW" in text


def _port_entry(**overrides) -> PortEntry:
    defaults = dict(
        port=5432,
        protocol="tcp",
        local_address="127.0.0.1",
        pid=222,
        command="postgres",
        exposed_to_network=False,
        service_name="PostgreSQL",
        risk="LOW",
        risk_note="Bound to localhost only.",
    )
    defaults.update(overrides)
    return PortEntry(**defaults)


def test_format_list_ports_summary_line_counts():
    entries = [
        _port_entry(port=22, pid=1, command="sshd", exposed_to_network=True, risk="HIGH"),
        _port_entry(port=5432, pid=2, command="postgres", exposed_to_network=False, risk="LOW"),
        _port_entry(port=3000, pid=3, command="node", exposed_to_network=True, risk="MEDIUM"),
    ]

    text = format_list_ports(entries)
    summary_line = text.splitlines()[0]

    assert summary_line == "3 listening ports, 2 exposed to network, 1 high risk"


def test_format_list_ports_groups_by_process():
    entries = [
        _port_entry(port=3000, pid=10, command="node"),
        _port_entry(port=3001, pid=10, command="node"),
        _port_entry(port=5432, pid=20, command="postgres"),
    ]

    text = format_list_ports(entries)

    # One "node:" heading covering both of its ports, not two separate blocks.
    assert text.count("node:") == 1
    assert "3000" in text and "3001" in text
    assert "postgres:" in text


def test_format_inspect_process_not_found():
    details = ProcessDetails(pid=999, ppid=None, user=None, command="", args="", found=False)
    assert "No process found" in format_inspect_process(details)


def test_format_inspect_process_found():
    details = ProcessDetails(pid=222, ppid=1, user="someuser", command="postgres", args="postgres -D /data", found=True)
    text = format_inspect_process(details)
    assert "222" in text
    assert "postgres" in text


def test_format_check_exposure_not_found():
    report = ExposureReport(port=1234, found=False)
    assert "not currently listening" in format_check_exposure(report)


def test_format_check_exposure_found():
    report = ExposureReport(
        port=22, found=True, exposed_to_network=True, local_address="*",
        service_name="SSH", risk="HIGH", risk_note="Exposed to all interfaces.",
    )
    text = format_check_exposure(report)
    assert "SSH" in text
    assert "HIGH" in text


@patch("mimoe_port_check.agent.list_ports")
def test_run_tool_dispatches_list_ports(mock_list_ports):
    mock_list_ports.return_value = []

    formatted, result = run_tool(Route(tool="list_ports", args={}, source="fallback"))

    assert formatted == "No listening TCP ports found."
    assert result == []
    mock_list_ports.assert_called_once()


@patch("mimoe_port_check.agent.inspect_process")
def test_run_tool_dispatches_inspect_process(mock_inspect):
    details = ProcessDetails(pid=1, ppid=None, user=None, command="", args="", found=False)
    mock_inspect.return_value = details

    formatted, result = run_tool(Route(tool="inspect_process", args={"pid": 1}, source="model"))

    assert result is details
    mock_inspect.assert_called_once_with(1)


@patch("mimoe_port_check.agent.check_exposure")
def test_run_tool_dispatches_check_exposure(mock_check):
    report = ExposureReport(port=80, found=False)
    mock_check.return_value = report

    formatted, result = run_tool(Route(tool="check_exposure", args={"port": 80}, source="model"))

    assert result is report
    mock_check.assert_called_once_with(80)


def test_summarize_notable_list_ports_filters_to_high_and_medium():
    entries = [
        _port_entry(port=22, pid=1, command="sshd", risk="HIGH", risk_note="Exposed."),
        _port_entry(port=5432, pid=2, command="postgres", risk="LOW"),
        _port_entry(port=3000, pid=3, command="node", risk="MEDIUM", risk_note="Exposed too."),
    ]

    summary = summarize_notable(Route(tool="list_ports", args={}, source="fallback"), entries)

    assert "sshd" in summary or "22" in summary
    assert "node" in summary or "3000" in summary
    assert "postgres" not in summary
    assert "5432" not in summary


def test_summarize_notable_list_ports_all_clear():
    entries = [_port_entry(risk="LOW"), _port_entry(port=80, pid=2, risk="INFO")]

    summary = summarize_notable(Route(tool="list_ports", args={}, source="fallback"), entries)

    assert "nothing notable" in summary.lower()


def test_summarize_notable_check_exposure_not_found():
    report = ExposureReport(port=9999, found=False)

    summary = summarize_notable(Route(tool="check_exposure", args={"port": 9999}, source="model"), report)

    assert "not currently listening" in summary


def test_summarize_notable_inspect_process_not_found():
    details = ProcessDetails(pid=123, ppid=None, user=None, command="", args="", found=False)

    summary = summarize_notable(Route(tool="inspect_process", args={"pid": 123}, source="model"), details)

    assert "No process found" in summary


def test_has_nothing_to_explain_true_for_port_not_listening():
    report = ExposureReport(port=9999, found=False)
    assert has_nothing_to_explain(Route(tool="check_exposure", args={"port": 9999}, source="model"), report) is True


def test_has_nothing_to_explain_true_for_pid_not_found():
    details = ProcessDetails(pid=123, ppid=None, user=None, command="", args="", found=False)
    assert has_nothing_to_explain(Route(tool="inspect_process", args={"pid": 123}, source="model"), details) is True


def test_has_nothing_to_explain_false_when_found():
    report = ExposureReport(port=22, found=True, service_name="SSH", risk="LOW")
    assert has_nothing_to_explain(Route(tool="check_exposure", args={"port": 22}, source="model"), report) is False


def test_has_nothing_to_explain_false_for_list_ports():
    assert has_nothing_to_explain(Route(tool="list_ports", args={}, source="fallback"), []) is False


def test_deterministic_explanation_port_not_listening():
    report = ExposureReport(port=9999, found=False)
    text = deterministic_explanation(Route(tool="check_exposure", args={"port": 9999}, source="model"), report)
    assert "9999" in text and "not currently listening" in text


def test_deterministic_explanation_pid_not_found():
    details = ProcessDetails(pid=123, ppid=None, user=None, command="", args="", found=False)
    text = deterministic_explanation(Route(tool="inspect_process", args={"pid": 123}, source="model"), details)
    assert "123" in text and "No process found" in text


@patch("mimoe_port_check.agent.route")
def test_resolve_route_reuses_context_for_referential_followup(mock_route):
    last = Route(tool="check_exposure", args={"port": 5432}, source="model")

    result = resolve_route("is it risky?", CONFIG, last)

    assert result.tool == "check_exposure"
    assert result.args == {"port": 5432}
    assert result.source == "context"
    mock_route.assert_not_called()


@patch("mimoe_port_check.agent.route")
def test_resolve_route_does_not_reuse_context_when_number_present(mock_route):
    mock_route.return_value = Route(tool="check_exposure", args={"port": 80}, source="model")
    last = Route(tool="check_exposure", args={"port": 5432}, source="model")

    resolve_route("what about port 80?", CONFIG, last)

    mock_route.assert_called_once()


@patch("mimoe_port_check.agent.route")
def test_resolve_route_falls_through_to_router_with_no_prior_context(mock_route):
    mock_route.return_value = Route(tool="list_ports", args={}, source="model")

    resolve_route("what's open?", CONFIG, None)

    mock_route.assert_called_once()


@patch("mimoe_port_check.agent.route")
def test_resolve_route_ignores_context_for_list_ports_last_tool(mock_route):
    mock_route.return_value = Route(tool="list_ports", args={}, source="model")
    last = Route(tool="list_ports", args={}, source="model")

    resolve_route("is it risky?", CONFIG, last)

    mock_route.assert_called_once()


@patch("mimoe_port_check.agent.route")
def test_resolve_route_forwards_debug_flag(mock_route):
    mock_route.return_value = Route(tool="list_ports", args={}, source="model")

    resolve_route("what's open?", CONFIG, None, debug=True)

    mock_route.assert_called_once_with("what's open?", CONFIG, debug=True)


def test_print_welcome_shows_smollm_tip(capsys):
    _print_welcome(Config(base_url=CONFIG.base_url, model="smollm-360m", api_key=CONFIG.api_key))

    assert "Tip" in capsys.readouterr().out


def test_print_welcome_no_tip_for_other_models(capsys):
    _print_welcome(Config(base_url=CONFIG.base_url, model="qwen3-1.7b", api_key=CONFIG.api_key))

    assert "Tip" not in capsys.readouterr().out


def test_find_ungrounded_claims_none_when_grounded():
    summary = "Port 8083 (mimOE): MEDIUM -- shared default API key."
    explanation = "Port 8083 is exposed and uses a shared key."

    assert find_ungrounded_claims(explanation, summary) == {}


def test_find_ungrounded_claims_flags_fabricated_port():
    summary = "Process 900 (rapportd), user=someuser, args=/usr/libexec/rapportd"
    explanation = "Process 900 is listening on port 5060 and port 5061."

    result = find_ungrounded_claims(explanation, summary)

    assert result == {"ports": {5060, 5061}}


def test_find_ungrounded_claims_flags_fabricated_pid():
    summary = "Port 8083 (mimOE): MEDIUM -- shared default API key."
    explanation = "This is managed by process 42."

    result = find_ungrounded_claims(explanation, summary)

    assert result == {"pids": {42}}


def test_find_ungrounded_claims_handles_plural_port_list():
    summary = "1 of 12 listening ports are notable:\n- mimOE on port 8083 (MEDIUM)"
    explanation = "Ports 8083 and 9090 are both open."

    result = find_ungrounded_claims(explanation, summary)

    # 8083 is grounded (in the summary); only 9090 is fabricated.
    assert result == {"ports": {9090}}


def test_find_ungrounded_claims_handles_plural_pid_list_with_commas():
    summary = "Process 900 (rapportd), user=someuser, args=/usr/libexec/rapportd"
    explanation = "PIDs 12, 34 also appear related."

    result = find_ungrounded_claims(explanation, summary)

    assert result == {"pids": {12, 34}}


def test_find_ungrounded_claims_handles_colon_separated_keyword():
    # e.g. "Port: 900" -- observed live from smollm-360m fabricating a
    # port field for a process-inspection result that has no port data.
    summary = "Process 900 (rapportd), user=someuser, args=/usr/libexec/rapportd"
    explanation = "Process 900 details:\n- Port: 900\n- Command: rap"

    result = find_ungrounded_claims(explanation, summary)

    assert result == {"ports": {900}}


def test_find_ungrounded_claims_ignores_numbers_without_keyword():
    # A bare number with no "port"/"pid"/"process" right before it is a
    # known blind spot of this heuristic -- documented, not a bug.
    summary = "Port 8083 (mimOE): MEDIUM -- shared default API key."
    explanation = "It's reachable at 5060 apparently."

    assert find_ungrounded_claims(explanation, summary) == {}


def test_is_on_topic_true_for_domain_questions():
    assert is_on_topic("what's open on my machine?") is True
    assert is_on_topic("tell me about process 512") is True


def test_is_on_topic_false_for_unrelated_questions():
    assert is_on_topic("what's the weather?") is False
    assert is_on_topic("run rm -rf ~") is False


def test_resolve_route_flags_off_topic_question():
    result = resolve_route("what's the weather?", CONFIG, None)
    assert result.tool == OFF_TOPIC_TOOL


def test_resolve_route_flags_destructive_off_topic_question():
    result = resolve_route("run rm -rf ~", CONFIG, None)
    assert result.tool == OFF_TOPIC_TOOL


def test_resolve_route_flags_invalid_pid_reference():
    result = resolve_route("process abc", CONFIG, None)
    assert result.tool == INVALID_PID_TOOL


def test_resolve_route_flags_unfilled_pid_placeholder():
    # A literal, unsubstituted "<PID>" token -- no digits, still on-topic
    # ("process"), so it must hit the invalid-input gate, not off-topic.
    result = resolve_route("tell me about process <PID>", CONFIG, None)
    assert result.tool == INVALID_PID_TOOL


def test_resolve_route_does_not_flag_valid_pid_question():
    with patch("mimoe_port_check.agent.route") as mock_route:
        mock_route.return_value = Route(tool="inspect_process", args={"pid": 512}, source="model")
        result = resolve_route("tell me about process 512", CONFIG, None)

    assert result.tool == "inspect_process"


def test_find_exposure_contradiction_double_negative_vs_exposed_summary():
    # Real live case: summary says exposed (MEDIUM, mimOE/shared-key note);
    # explanation says "not exposed" twice and never says a standalone
    # "exposed" -- a naive substring check for "exposed" would wrongly
    # conclude the explanation agreed with the summary.
    summary = (
        "1 of 12 listening ports are notable:\n"
        "- mimOE on port 8083 (pid 900): MEDIUM -- Local AI inference "
        "endpoint used by this agent. Exposed to all network interfaces "
        "-- the API key is a shared default, so anyone on the local "
        "network could reach and use this inference endpoint."
    )
    explanation = (
        "It is not exposed to all network interfaces. It is not exposed "
        "to any network interfaces."
    )

    warning = find_exposure_contradiction(explanation, summary)

    assert warning is not None


def test_find_exposure_contradiction_flags_explanation_says_exposed():
    summary = "Port 5432 (PostgreSQL): LOW -- Bound to localhost only."
    explanation = "Port 5432 is exposed to the network."

    warning = find_exposure_contradiction(explanation, summary)

    assert warning is not None


def test_find_exposure_contradiction_none_when_agreeing():
    summary = "Port 5432 (PostgreSQL): LOW -- Bound to localhost only."
    explanation = "Port 5432 is not exposed; it's bound to localhost only."

    assert find_exposure_contradiction(explanation, summary) is None


def test_find_exposure_contradiction_none_when_neither_mentions_exposure():
    summary = "No process found with PID 512."
    explanation = "There's no process running with that PID."

    assert find_exposure_contradiction(explanation, summary) is None


def test_find_exposure_contradiction_none_when_summary_is_ambiguous():
    # A multi-finding summary mentioning both directions -- left alone
    # rather than guessed at, per the heuristic's documented limits.
    summary = "Port 22: exposed to the network. Port 5432: not exposed, localhost only."
    explanation = "Port 22 is exposed to the network."

    assert find_exposure_contradiction(explanation, summary) is None


def test_trim_to_complete_sentence_drops_incomplete_trailing_fragment():
    # Real observed shape: a repeated sentence, then cut off mid-way
    # through another repetition when max_tokens ran out.
    text = "Port 8083 is exposed. Consider restricting access. The agent is listening on port 8"

    assert trim_to_complete_sentence(text) == "Port 8083 is exposed. Consider restricting access."


def test_trim_to_complete_sentence_leaves_complete_text_alone():
    text = "Port 8083 is exposed. Consider restricting access."

    assert trim_to_complete_sentence(text) == text


def test_trim_to_complete_sentence_returns_original_when_no_sentence_end_found():
    text = "```bash\nnetstat -an | grep something"

    assert trim_to_complete_sentence(text) == text


def test_trim_to_complete_sentence_avoids_bad_cut_inside_ip_address():
    # Without requiring whitespace/end-of-text after the punctuation, a
    # naive "last '.' anywhere" search would cut inside 127.0.0.1 itself,
    # producing "...bound to 127.0.0" -- worse than leaving the (still
    # incomplete) fragment alone.
    text = "The endpoint is bound to 127.0.0.1, not the network"

    assert trim_to_complete_sentence(text) == text


def test_trim_to_complete_sentence_keeps_full_text_past_abbreviation():
    # "e.g." has periods followed by whitespace mid-sentence; the function
    # must still find the true final period, not stop at "e.g.".
    text = "Consider changing the key, e.g. to a random value, for better security."

    assert trim_to_complete_sentence(text) == text
