import http.client
import json
import threading
from http.server import HTTPServer
from unittest.mock import patch

import pytest

from mimoe_port_check.agent import QuestionResult
from mimoe_port_check.config import Config
from mimoe_port_check.router import Route
from mimoe_port_check.tools import PortEntry
from mimoe_port_check.web import (
    MAX_BODY_BYTES,
    MAX_QUESTION_LENGTH,
    Handler,
    is_trusted_host,
    is_trusted_origin,
    serialize_question_result,
)

CONFIG = Config(
    base_url="http://localhost:8083/mimik-ai/openai/v1",
    model="smollm-360m",
    api_key="1234",
)


# --- pure functions: Host/Origin validation, serialization ---


def test_is_trusted_host_accepts_localhost_and_loopback():
    assert is_trusted_host("localhost:8090") is True
    assert is_trusted_host("127.0.0.1:8090") is True
    assert is_trusted_host("localhost") is True
    assert is_trusted_host("[::1]:8090") is True


def test_is_trusted_host_rejects_lookalike_and_missing():
    # A prefix/substring check would wrongly accept this -- DNS rebinding
    # relies on exactly this kind of lookalike hostname.
    assert is_trusted_host("127.0.0.1.evil.com:8090") is False
    assert is_trusted_host("evil.com") is False
    assert is_trusted_host(None) is False
    assert is_trusted_host("") is False


def test_is_trusted_origin_allows_absent_origin():
    # Same-origin fetch() calls and non-browser clients don't send Origin;
    # Host validation is the primary defense for those.
    assert is_trusted_origin(None, 8090) is True


def test_is_trusted_origin_accepts_matching_scheme_host_and_port():
    assert is_trusted_origin("http://localhost:8090", 8090) is True
    assert is_trusted_origin("http://127.0.0.1:8090", 8090) is True


def test_is_trusted_origin_rejects_wrong_port_host_or_scheme():
    assert is_trusted_origin("http://localhost:1234", 8090) is False
    assert is_trusted_origin("http://evil.com:8090", 8090) is False
    assert is_trusted_origin("https://localhost:8090", 8090) is False


def _port_entry(**overrides) -> PortEntry:
    defaults = dict(
        port=22, protocol="tcp", local_address="*", pid=411, command="sshd",
        exposed_to_network=True, service_name="SSH", risk="HIGH", risk_note="Exposed.",
    )
    defaults.update(overrides)
    return PortEntry(**defaults)


def test_serialize_question_result_list_ports():
    route = Route(tool="list_ports", args={}, source="fallback")
    result = QuestionResult(
        route=route, model="smollm-360m", findings_text="1 listening port",
        findings_data=[_port_entry()], explanation="SSH is exposed.", warnings=["something"],
    )

    serialized = serialize_question_result(result)

    assert serialized["route"] == {"tool": "list_ports", "args": {}, "source": "fallback"}
    assert serialized["findings"]["kind"] == "list_ports"
    assert serialized["findings"]["entries"][0]["port"] == 22
    assert serialized["findings"]["summary"] == "1 listening port, 1 exposed to network, 1 high risk"
    assert serialized["explanation"] == "SSH is exposed."
    assert serialized["warnings"] == ["something"]


def test_serialize_question_result_none_findings_for_off_topic():
    route = Route(tool="off_topic", args={}, source="off_topic")
    result = QuestionResult(
        route=route, model="smollm-360m", findings_text=None,
        findings_data=None, explanation="I can only help with...", warnings=[],
    )

    serialized = serialize_question_result(result)

    assert serialized["findings"] is None


# --- real server, end to end ---


@pytest.fixture
def server():
    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    httpd.config = CONFIG
    httpd.last_route = None
    httpd.debug = False
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)


def _connection(server) -> http.client.HTTPConnection:
    return http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)


def test_server_binds_to_loopback_only(server):
    assert server.server_address[0] == "127.0.0.1"


def test_get_index_serves_html(server):
    conn = _connection(server)
    conn.request("GET", "/")
    resp = conn.getresponse()
    body = resp.read()
    conn.close()

    assert resp.status == 200
    assert b"mimoe-port-check" in body


def test_get_status(server):
    conn = _connection(server)
    conn.request("GET", "/api/status")
    resp = conn.getresponse()
    data = json.loads(resp.read())
    conn.close()

    assert resp.status == 200
    assert data["model"] == "smollm-360m"
    assert data["tip"]  # smollm-360m always gets the tip


def test_unknown_path_is_404(server):
    conn = _connection(server)
    conn.request("GET", "/nope")
    resp = conn.getresponse()
    resp.read()
    conn.close()

    assert resp.status == 404


def test_response_never_includes_cors_header(server):
    conn = _connection(server)
    conn.request("GET", "/api/status")
    resp = conn.getresponse()
    resp.read()
    conn.close()

    assert resp.getheader("Access-Control-Allow-Origin") is None


def test_untrusted_host_header_rejected(server):
    conn = _connection(server)
    # skip_host=True so we control the exact Host header sent, instead of
    # http.client silently adding a second, correct one alongside it.
    conn.putrequest("GET", "/api/status", skip_host=True)
    conn.putheader("Host", "evil.com")
    conn.endheaders()
    resp = conn.getresponse()
    resp.read()
    conn.close()

    assert resp.status == 400


def test_untrusted_origin_header_rejected(server):
    conn = _connection(server)
    conn.request("GET", "/api/status", headers={"Origin": "http://evil.com"})
    resp = conn.getresponse()
    resp.read()
    conn.close()

    assert resp.status == 403


def test_trusted_origin_is_allowed(server):
    port = server.server_address[1]
    conn = _connection(server)
    conn.request("GET", "/api/status", headers={"Origin": f"http://localhost:{port}"})
    resp = conn.getresponse()
    resp.read()
    conn.close()

    assert resp.status == 200


@patch("mimoe_port_check.web.process_question")
def test_post_ask_round_trip(mock_process_question, server):
    route = Route(tool="list_ports", args={}, source="fallback")
    mock_process_question.return_value = QuestionResult(
        route=route, model="smollm-360m", findings_text="1 listening port",
        findings_data=[], explanation="All clear.", warnings=[],
    )

    conn = _connection(server)
    body = json.dumps({"question": "what's open?"}).encode()
    conn.request(
        "POST", "/api/ask", body=body,
        headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
    )
    resp = conn.getresponse()
    data = json.loads(resp.read())
    conn.close()

    assert resp.status == 200
    assert data["explanation"] == "All clear."
    assert server.last_route is route  # follow-up context updated


@patch("mimoe_port_check.web.os.getpid", return_value=4242)
@patch("mimoe_port_check.web.process_question")
def test_post_ask_forwards_own_pid_for_self_port_labeling(mock_process_question, mock_getpid, server):
    # So list_ports/check_exposure can label the web UI's own listening
    # port instead of showing it as an unrecognized service -- see
    # tools.label_risk's self_pid parameter.
    route = Route(tool="list_ports", args={}, source="fallback")
    mock_process_question.return_value = QuestionResult(
        route=route, model="smollm-360m", findings_text="1 listening port",
        findings_data=[], explanation="All clear.", warnings=[],
    )

    conn = _connection(server)
    body = json.dumps({"question": "what's open?"}).encode()
    conn.request(
        "POST", "/api/ask", body=body,
        headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
    )
    resp = conn.getresponse()
    resp.read()
    conn.close()

    assert resp.status == 200
    assert mock_process_question.call_args.kwargs["self_pid"] == 4242


@patch("mimoe_port_check.web.process_question")
def test_post_ask_off_topic_does_not_clobber_last_route(mock_process_question, server):
    # Regression: last_route was updated unconditionally, so an off-topic
    # question in between two real ones broke the next referential
    # follow-up. Seed last_route with a real prior route, then send an
    # off-topic result and confirm last_route is untouched.
    real_route = Route(tool="check_exposure", args={"port": 22}, source="model")
    server.last_route = real_route
    off_topic_route = Route(tool="off_topic", args={}, source="off_topic")
    mock_process_question.return_value = QuestionResult(
        route=off_topic_route, model="smollm-360m", findings_text=None,
        findings_data=None, explanation="I can only help with...", warnings=[],
    )

    conn = _connection(server)
    body = json.dumps({"question": "what's the weather?"}).encode()
    conn.request(
        "POST", "/api/ask", body=body,
        headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
    )
    resp = conn.getresponse()
    resp.read()
    conn.close()

    assert resp.status == 200
    assert server.last_route is real_route


def test_post_ask_non_ascii_digit_content_length_rejected_gracefully(server):
    # str.isdigit() returns True for non-ASCII Unicode digits that int()
    # then rejects -- must fail as a clean 400, not an unhandled ValueError.
    body = json.dumps({"question": "what's open?"}).encode()

    conn = _connection(server)
    conn.putrequest("POST", "/api/ask")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", "²")  # superscript "2", isdigit() == True
    conn.endheaders()
    conn.send(body)
    resp = conn.getresponse()
    data = json.loads(resp.read())
    conn.close()

    assert resp.status == 400
    assert "error" in data


@patch("mimoe_port_check.web.process_question")
def test_post_ask_tool_error_message_includes_tool_name(mock_process_question, server):
    mock_process_question.side_effect = RuntimeError("'inspect_process': boom")

    conn = _connection(server)
    body = json.dumps({"question": "tell me about process 512"}).encode()
    conn.request(
        "POST", "/api/ask", body=body,
        headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
    )
    resp = conn.getresponse()
    data = json.loads(resp.read())
    conn.close()

    assert resp.status == 500
    assert "inspect_process" in data["error"]


def test_post_ask_body_too_large_rejected(server):
    conn = _connection(server)
    body = json.dumps({"question": "a" * (MAX_BODY_BYTES + 100)}).encode()
    conn.request(
        "POST", "/api/ask", body=body,
        headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
    )
    resp = conn.getresponse()
    resp.read()
    conn.close()

    assert resp.status == 413


def test_post_ask_question_too_long_rejected(server):
    body = json.dumps({"question": "a" * (MAX_QUESTION_LENGTH + 1)}).encode()
    assert len(body) <= MAX_BODY_BYTES  # this test targets the length check, not the size cap

    conn = _connection(server)
    conn.request(
        "POST", "/api/ask", body=body,
        headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
    )
    resp = conn.getresponse()
    data = json.loads(resp.read())
    conn.close()

    assert resp.status == 400
    assert "error" in data


def test_post_ask_empty_question_rejected(server):
    body = json.dumps({"question": "   "}).encode()

    conn = _connection(server)
    conn.request(
        "POST", "/api/ask", body=body,
        headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
    )
    resp = conn.getresponse()
    resp.read()
    conn.close()

    assert resp.status == 400


def test_post_ask_malformed_json_rejected(server):
    body = b"not json"

    conn = _connection(server)
    conn.request(
        "POST", "/api/ask", body=body,
        headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
    )
    resp = conn.getresponse()
    resp.read()
    conn.close()

    assert resp.status == 400


def test_post_ask_non_string_question_rejected(server):
    body = json.dumps({"question": 12345}).encode()

    conn = _connection(server)
    conn.request(
        "POST", "/api/ask", body=body,
        headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
    )
    resp = conn.getresponse()
    resp.read()
    conn.close()

    assert resp.status == 400


@patch("mimoe_port_check.web.process_question")
def test_post_ask_untrusted_host_rejected_before_processing(mock_process_question, server):
    conn = _connection(server)
    body = json.dumps({"question": "what's open?"}).encode()
    conn.putrequest("POST", "/api/ask", skip_host=True)
    conn.putheader("Host", "evil.com")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", str(len(body)))
    conn.endheaders()
    conn.send(body)
    resp = conn.getresponse()
    resp.read()
    conn.close()

    assert resp.status == 400
    mock_process_question.assert_not_called()
