from unittest.mock import Mock, patch

import pytest

from mimoe_port_check.tools import (
    check_exposure,
    inspect_process,
    list_ports,
    redact_secrets,
)
from mimoe_port_check.tools import _decode_lsof_escapes

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


@patch("mimoe_port_check.tools.subprocess.run")
def test_list_ports_parses_listen_entries_only(mock_run):
    mock_run.return_value = _mock_result(FAKE_LSOF_OUTPUT)

    entries = list_ports()
    ports = {e.port for e in entries}

    # Only the 4 LISTEN lines should be included; UDP and ESTABLISHED excluded.
    assert ports == {22, 5432, 8083, 41999}


@patch("mimoe_port_check.tools.subprocess.run")
def test_list_ports_flags_network_exposure(mock_run):
    mock_run.return_value = _mock_result(FAKE_LSOF_OUTPUT)

    entries = {e.port: e for e in list_ports()}

    assert entries[22].exposed_to_network is True  # bound to *
    assert entries[5432].exposed_to_network is False  # bound to 127.0.0.1


@patch("mimoe_port_check.tools.subprocess.run")
def test_list_ports_labels_known_and_unknown_services(mock_run):
    mock_run.return_value = _mock_result(FAKE_LSOF_OUTPUT)

    entries = {e.port: e for e in list_ports()}

    assert entries[22].service_name == "SSH"
    assert entries[22].risk == "HIGH"  # sensitive service exposed to all interfaces
    assert entries[5432].service_name == "PostgreSQL"
    assert entries[5432].risk == "LOW"  # localhost only
    assert entries[41999].service_name == "Unknown service"
    assert entries[41999].risk == "MEDIUM"  # unknown port exposed to all interfaces


FAKE_LSOF_DUAL_STACK = """COMMAND    PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
devsrv     777  someuser    3u  IPv4    0x1      0t0  TCP *:3000 (LISTEN)
devsrv     777  someuser    4u  IPv6    0x2      0t0  TCP [::]:3000 (LISTEN)
lonely     888  someuser    5u  IPv4    0x3      0t0  TCP 127.0.0.1:9000 (LISTEN)
"""


@patch("mimoe_port_check.tools.subprocess.run")
def test_list_ports_merges_dual_stack_entries(mock_run):
    mock_run.return_value = _mock_result(FAKE_LSOF_DUAL_STACK)

    entries = list_ports()
    by_port = {e.port: e for e in entries}

    # The IPv4 and IPv6 rows for devsrv/777/3000 collapse into one entry.
    assert len(entries) == 2
    assert by_port[3000].pid == 777
    assert by_port[3000].exposed_to_network is True
    assert "*" in by_port[3000].local_address
    assert "[::]" in by_port[3000].local_address
    # A single-stack entry is untouched.
    assert by_port[9000].local_address == "127.0.0.1"


FAKE_LSOF_ESCAPED_COMMAND = """COMMAND    PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
Code\\x20Helper 999  someuser    3u  IPv4    0x1      0t0  TCP 127.0.0.1:9222 (LISTEN)
"""


@patch("mimoe_port_check.tools.subprocess.run")
def test_list_ports_decodes_lsof_command_escapes(mock_run):
    mock_run.return_value = _mock_result(FAKE_LSOF_ESCAPED_COMMAND)

    entries = list_ports()

    assert entries[0].command == "Code Helper"


def test_decode_lsof_escapes_handles_multiple_escapes():
    assert _decode_lsof_escapes("Code\\x20Helper\\x20(Plugin)") == "Code Helper (Plugin)"


def test_decode_lsof_escapes_leaves_normal_text_alone():
    assert _decode_lsof_escapes("postgres") == "postgres"


FAKE_LSOF_RAPPORTD = """COMMAND    PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
rapportd   700  someuser    3u  IPv4    0x1      0t0  TCP 127.0.0.1:49152 (LISTEN)
"""

FAKE_LSOF_SPOTIFY_EXPOSED = """COMMAND    PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
Spotify    800  someuser    3u  IPv4    0x1      0t0  TCP *:57621 (LISTEN)
"""

FAKE_LSOF_MIMOE = """COMMAND    PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
mimoe      900  someuser    3u  IPv4    0x1      0t0  TCP 127.0.0.1:8083 (LISTEN)
"""


def _fake_run_lsof_then_ps(lsof_output: str, ps_output: str):
    def fake_run(args, **kwargs):
        if args[0] == "lsof":
            return _mock_result(lsof_output)
        if args[0] == "ps":
            return _mock_result(ps_output)
        raise AssertionError(f"unexpected command: {args}")

    return fake_run


@patch("mimoe_port_check.tools.subprocess.run")
def test_list_ports_labels_known_process_with_verified_path(mock_run):
    mock_run.side_effect = _fake_run_lsof_then_ps(
        FAKE_LSOF_RAPPORTD, "/usr/libexec/rapportd\n"
    )

    entries = list_ports()

    assert entries[0].service_name == "Handoff/Continuity"
    assert entries[0].risk == "LOW"


@patch("mimoe_port_check.tools.subprocess.run")
def test_list_ports_falls_back_when_path_does_not_match(mock_run):
    # Something named "rapportd" but not actually running from Apple's path
    # -- spoofed name, must not get the trusted label.
    mock_run.side_effect = _fake_run_lsof_then_ps(
        FAKE_LSOF_RAPPORTD, "/tmp/evil/rapportd\n"
    )

    entries = list_ports()

    assert entries[0].service_name != "Handoff/Continuity"
    assert entries[0].service_name == "Unknown service"


@patch("mimoe_port_check.tools.subprocess.run")
def test_list_ports_labels_exposed_known_process_as_info(mock_run):
    mock_run.side_effect = _fake_run_lsof_then_ps(
        FAKE_LSOF_SPOTIFY_EXPOSED, "/Applications/Spotify.app/Contents/MacOS/Spotify\n"
    )

    entries = list_ports()

    assert entries[0].service_name == "Spotify Connect"
    assert entries[0].risk == "INFO"


@patch("mimoe_port_check.tools.subprocess.run")
def test_list_ports_labels_known_process_with_no_fixed_path_by_name_only(mock_run):
    mock_run.return_value = _mock_result(FAKE_LSOF_MIMOE)

    entries = list_ports()

    assert entries[0].service_name == "mimOE"
    assert entries[0].risk == "LOW"
    mock_run.assert_called_once()  # no extra `ps` lookup needed -- no path to verify


@patch("mimoe_port_check.tools.subprocess.run")
def test_check_exposure_found(mock_run):
    mock_run.return_value = _mock_result(FAKE_LSOF_OUTPUT)

    report = check_exposure(22)

    assert report.found is True
    assert report.exposed_to_network is True
    assert report.service_name == "SSH"


@patch("mimoe_port_check.tools.subprocess.run")
def test_check_exposure_not_found(mock_run):
    mock_run.return_value = _mock_result(FAKE_LSOF_OUTPUT)

    report = check_exposure(9999)

    assert report.found is False


def test_check_exposure_rejects_bad_port():
    with pytest.raises(ValueError):
        check_exposure(70000)
    with pytest.raises(ValueError):
        check_exposure("22")  # type: ignore[arg-type]


@patch("mimoe_port_check.tools.subprocess.run")
def test_inspect_process_parses_ps_output(mock_run):
    mock_run.return_value = _mock_result("222   1 someuser postgres /usr/local/bin/postgres -D /data\n")

    details = inspect_process(222)

    assert details.found is True
    assert details.pid == 222
    assert details.ppid == 1
    assert details.user == "someuser"
    assert details.command == "postgres"


@patch("mimoe_port_check.tools.subprocess.run")
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


@patch("mimoe_port_check.tools.subprocess.run")
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
