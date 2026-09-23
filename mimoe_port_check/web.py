"""Minimal local web UI: the same core pipeline as the CLI
(agent.process_question), served over a tiny stdlib HTTP server. See the
README "Web UI" section for how to run it and why each security check
below exists.

Deliberately single-threaded (plain HTTPServer, not ThreadingHTTPServer):
this agent keeps one global, process-wide "last route" for follow-up
questions (see run_server) rather than per-session state, since this is a
single-operator localhost tool, not a multi-user service. A threaded
server could interleave two requests' read-modify-write of that global and
corrupt it; single-threaded handling makes that impossible by construction.
"""
import dataclasses
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .agent import MimOEPhaseError, QuestionResult, list_ports_summary, model_tip, process_question, resolve_config
from .config import LOCALHOST_HOSTS
from .router import Route

STATIC_DIR = Path(__file__).resolve().parent / "static"
INDEX_PATH = STATIC_DIR / "index.html"

# Caps chosen generously for a chat-style question, tightly enough to
# reject anything that isn't one. Enforced before process_question ever
# runs, so an oversized/malformed request never reaches the model.
MAX_BODY_BYTES = 4096
MAX_QUESTION_LENGTH = 500


def is_trusted_host(host_header: str | None) -> bool:
    """DNS-rebinding defense: a rebinding attack gets the browser to
    connect to 127.0.0.1 at the network level while it still believes (and
    sends, in the Host header) the attacker's original hostname. Exact
    hostname match after parsing off the port -- not a prefix/substring
    check, which "127.0.0.1.evil.com" would otherwise slip past."""
    if not host_header:
        return False
    hostname = urlparse(f"http://{host_header}").hostname
    return hostname in LOCALHOST_HOSTS


def is_trusted_origin(origin_header: str | None, server_port: int) -> bool:
    """When present, Origin must exactly match this server's own
    http://localhost|127.0.0.1:<port> origin. Absent is allowed because
    non-browser clients like curl don't send one; the Host check above is
    the primary defense."""
    if not origin_header:
        return True
    try:
        parsed = urlparse(origin_header)
    except ValueError:
        return False
    if parsed.scheme != "http" or parsed.hostname not in LOCALHOST_HOSTS:
        return False
    return parsed.port == server_port


def _serialize_findings(route: Route, findings_data) -> dict | None:
    if findings_data is None:
        return None
    if route.tool == "list_ports":
        return {
            "kind": "list_ports",
            "summary": list_ports_summary(findings_data),
            "entries": [dataclasses.asdict(entry) for entry in findings_data],
        }
    if route.tool in ("check_exposure", "inspect_process"):
        return {"kind": route.tool, **dataclasses.asdict(findings_data)}
    return None


def serialize_question_result(result: QuestionResult) -> dict:
    return {
        "model": result.model,
        "route": {"tool": result.route.tool, "args": result.route.args, "source": result.route.source},
        "findings": _serialize_findings(result.route, result.findings_data),
        "explanation": result.explanation,
        "warnings": result.warnings,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "mimoe-port-check-ui/1"

    def log_message(self, format: str, *args) -> None:
        pass  # keep the console quiet; nothing sensitive would be logged anyway

    def _write_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Deliberately no Access-Control-Allow-Origin (or any other CORS
        # header): a cross-origin fetch() with a JSON body triggers a
        # preflight OPTIONS first, which this server doesn't answer with
        # permission for any origin, so the browser blocks the real
        # request before it's sent. A plain HTML form can't set
        # Content-Type: application/json, so it can't hit this endpoint
        # as a simple (non-preflighted) cross-origin request either.
        self.end_headers()
        self.wfile.write(body)

    def _reject(self, status: int, message: str) -> None:
        self._write_json(status, {"error": message})

    def _check_host_and_origin(self) -> bool:
        if not is_trusted_host(self.headers.get("Host")):
            self._reject(400, "untrusted Host header")
            return False
        if not is_trusted_origin(self.headers.get("Origin"), self.server.server_port):
            self._reject(403, "untrusted Origin header")
            return False
        return True

    def do_GET(self) -> None:
        if not self._check_host_and_origin():
            return
        if self.path == "/":
            self._serve_index()
        elif self.path == "/api/status":
            self._serve_status()
        else:
            self._reject(404, "not found")

    def _serve_index(self) -> None:
        html = INDEX_PATH.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def _serve_status(self) -> None:
        config = self.server.config
        self._write_json(200, {"model": config.model, "tip": model_tip(config.model)})

    def _read_json_body(self) -> dict | None:
        """Enforce Content-Length and MAX_BODY_BYTES, then parse the body
        as a JSON object. Writes the rejection response itself and
        returns None on any failure, so callers can just check for
        None."""
        # int() directly, not str.isdigit() first: isdigit() returns True
        # for non-ASCII Unicode digits (e.g. "²") that int() then
        # rejects, which would otherwise raise an uncaught ValueError here
        # instead of the intended graceful 400.
        try:
            content_length = int(self.headers.get("Content-Length"))
        except (TypeError, ValueError):
            self._reject(400, "missing or invalid Content-Length")
            return None
        if content_length < 0:
            self._reject(400, "missing or invalid Content-Length")
            return None

        if content_length > MAX_BODY_BYTES:
            self._reject(413, f"request body too large (max {MAX_BODY_BYTES} bytes)")
            return None

        raw_body = self.rfile.read(content_length)
        try:
            payload = json.loads(raw_body)
        except json.JSONDecodeError:
            self._reject(400, "invalid JSON body")
            return None

        if not isinstance(payload, dict):
            self._reject(400, "request body must be a JSON object")
            return None
        return payload

    def do_POST(self) -> None:
        if not self._check_host_and_origin():
            return
        if self.path != "/api/ask":
            self._reject(404, "not found")
            return
        self._handle_ask()

    def _handle_ask(self) -> None:
        payload = self._read_json_body()
        if payload is None:
            return

        if not isinstance(payload.get("question"), str):
            self._reject(400, "'question' must be a string")
            return

        question = payload["question"].strip()
        if not question:
            self._reject(400, "'question' must not be empty")
            return
        if len(question) > MAX_QUESTION_LENGTH:
            self._reject(400, f"'question' is too long (max {MAX_QUESTION_LENGTH} characters)")
            return

        try:
            result = process_question(
                question, self.server.config, self.server.last_route,
                debug=self.server.debug, self_pid=os.getpid(),
            )
        except MimOEPhaseError as exc:
            self._reject(502, f"could not reach mimOE {exc.phase_context}: {exc}")
            return
        except (ValueError, RuntimeError) as exc:
            self._reject(500, f"error running tool {exc}")
            return

        if result.findings_text is not None:
            # Off-topic/invalid-PID results are deliberately excluded: they
            # aren't a real tool result, so they must not clobber the last
            # real route a referential follow-up ("is it risky?") would reuse.
            self.server.last_route = result.route
        self._write_json(200, serialize_question_result(result))


def run_server(host: str = "127.0.0.1", port: int = 8090, debug: bool = False) -> None:
    if host != "127.0.0.1":
        raise ValueError("this server only ever binds to 127.0.0.1 -- see README Security")

    config = resolve_config()

    server = HTTPServer((host, port), Handler)
    server.config = config
    server.last_route: Route | None = None
    server.debug = debug

    print("mimoe-port-check web UI -- local, single-user")
    print(f"http://{host}:{port}")
    print(f"Connected to {config.base_url} (model: {config.model})")
    tip = model_tip(config.model)
    if tip:
        print(tip)
    print("Ctrl-C to stop.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        server.server_close()


if __name__ == "__main__":
    run_server()
