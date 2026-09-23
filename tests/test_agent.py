from unittest.mock import patch

from mimoe_port_check.agent import format_check_exposure, format_inspect_process, format_list_ports, resolve_route, run_tool
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

    result = run_tool(Route(tool="list_ports", args={}, source="fallback"))

    assert result == "No listening TCP ports found."
    mock_list_ports.assert_called_once()


@patch("mimoe_port_check.agent.inspect_process")
def test_run_tool_dispatches_inspect_process(mock_inspect):
    mock_inspect.return_value = ProcessDetails(pid=1, ppid=None, user=None, command="", args="", found=False)

    run_tool(Route(tool="inspect_process", args={"pid": 1}, source="model"))

    mock_inspect.assert_called_once_with(1)


@patch("mimoe_port_check.agent.check_exposure")
def test_run_tool_dispatches_check_exposure(mock_check):
    mock_check.return_value = ExposureReport(port=80, found=False)

    run_tool(Route(tool="check_exposure", args={"port": 80}, source="model"))

    mock_check.assert_called_once_with(80)


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
