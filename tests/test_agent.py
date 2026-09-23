from unittest.mock import patch

from mimoe_port_check.agent import (
    deterministic_explanation,
    format_check_exposure,
    format_inspect_process,
    format_list_ports,
    has_nothing_to_explain,
    resolve_route,
    run_tool,
    summarize_notable,
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
