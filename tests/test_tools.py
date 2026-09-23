from unittest.mock import Mock, patch

import pytest

from mimoe_port_scout.tools import (
    check_exposure,
    inspect_process,
    list_ports,
    redact_secrets,
)

# All lsof/ps output below is fake sample data, not real output from any machine.
FAKE_LSOF_OUTPUT = """COMMAND    PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
sshd       111  someuser    3u  IPv4    0x1      0t0  TCP *:22 (LISTEN)
postgres   222  someuser    5u  IPv4    0x2      0t0  TCP 127.0.0.1:5432 (LISTEN)
mimoe      333  someuser    7u  IPv4    0x3      0t0  TCP 127.0.0.1:8083 (LISTEN)
mystery    444  someuser    9u  IPv4    0x4      0t0  TCP *:41999 (LISTEN)
chatapp    555  someuser   11u  IPv4    0x5      0t0  UDP *:53
browser    666  someuser   13u  IPv4    0x6      0t0  TCP 127.0.0.1:60123->127.0.0.1:443 (ESTABLISHED)
"""


def _mock_result(stdout: str) -> Mock:
    result = Mock()
    result.stdout = stdout
    return result


@patch("mimoe_port_scout.tools.subprocess.run")
def test_list_ports_parses_listen_entries_only(mock_run):
    mock_run.return_value = _mock_result(FAKE_LSOF_OUTPUT)

    entries = list_ports()
    ports = {e.port for e in entries}

    # Only the 4 LISTEN lines should be included; UDP and ESTABLISHED excluded.
    assert ports == {22, 5432, 8083, 41999}


@patch("mimoe_port_scout.tools.subprocess.run")
def test_list_ports_flags_network_exposure(mock_run):
    mock_run.return_value = _mock_result(FAKE_LSOF_OUTPUT)

    entries = {e.port: e for e in list_ports()}

    assert entries[22].exposed_to_network is True  # bound to *
    assert entries[5432].exposed_to_network is False  # bound to 127.0.0.1


@patch("mimoe_port_scout.tools.subprocess.run")
def test_list_ports_labels_known_and_unknown_services(mock_run):
    mock_run.return_value = _mock_result(FAKE_LSOF_OUTPUT)

    entries = {e.port: e for e in list_ports()}

    assert entries[22].service_name == "SSH"
    assert entries[22].risk == "HIGH"  # sensitive service exposed to all interfaces
    assert entries[5432].service_name == "PostgreSQL"
    assert entries[5432].risk == "LOW"  # localhost only
    assert entries[41999].service_name == "Unknown service"
    assert entries[41999].risk == "MEDIUM"  # unknown port exposed to all interfaces


@patch("mimoe_port_scout.tools.subprocess.run")
def test_check_exposure_found(mock_run):
    mock_run.return_value = _mock_result(FAKE_LSOF_OUTPUT)

    report = check_exposure(22)

    assert report.found is True
    assert report.exposed_to_network is True
    assert report.service_name == "SSH"


@patch("mimoe_port_scout.tools.subprocess.run")
def test_check_exposure_not_found(mock_run):
    mock_run.return_value = _mock_result(FAKE_LSOF_OUTPUT)

    report = check_exposure(9999)

    assert report.found is False


def test_check_exposure_rejects_bad_port():
    with pytest.raises(ValueError):
        check_exposure(70000)
    with pytest.raises(ValueError):
        check_exposure("22")  # type: ignore[arg-type]


@patch("mimoe_port_scout.tools.subprocess.run")
def test_inspect_process_parses_ps_output(mock_run):
    mock_run.return_value = _mock_result("222   1 someuser postgres /usr/local/bin/postgres -D /data\n")

    details = inspect_process(222)

    assert details.found is True
    assert details.pid == 222
    assert details.ppid == 1
    assert details.user == "someuser"
    assert details.command == "postgres"


@patch("mimoe_port_scout.tools.subprocess.run")
def test_inspect_process_not_found(mock_run):
    mock_run.return_value = _mock_result("")

    details = inspect_process(99999)

    assert details.found is False


def test_inspect_process_rejects_bad_pid():
    with pytest.raises(ValueError):
        inspect_process(-1)
    with pytest.raises(ValueError):
        inspect_process("222")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        inspect_process(True)  # bool is a subclass of int, must be rejected


@patch("mimoe_port_scout.tools.subprocess.run")
def test_inspect_process_redacts_secrets_in_args(mock_run):
    mock_run.return_value = _mock_result(
        "222   1 someuser myapp /usr/local/bin/myapp --password=hunter2 --port=9999\n"
    )

    details = inspect_process(222)

    assert "hunter2" not in details.args
    assert "[REDACTED]" in details.args


def test_redact_secrets_masks_common_patterns():
    assert "hunter2" not in redact_secrets("--password=hunter2")
    assert "hunter2" not in redact_secrets("password=hunter2")
    assert "s3cr3t" not in redact_secrets("token=s3cr3t")
    assert "abcd" not in redact_secrets(
        "postgres://user:abcd1234@db.example.com:5432/mydb"
    )
    assert "eyabcxyz" not in redact_secrets("Authorization: Bearer eyabcxyz")


def test_redact_secrets_leaves_normal_text_alone():
    assert redact_secrets("postgres -D /usr/local/var/postgres") == (
        "postgres -D /usr/local/var/postgres"
    )
