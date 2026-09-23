#!/usr/bin/env python3
import argparse

from mimoe_port_check.web import run_server

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="mimoe-port-check -- local web UI")
    parser.add_argument("--port", type=int, default=8090, help="Port to listen on (default: 8090).")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print the model's raw tool-choice output for every routing decision.",
    )
    args = parser.parse_args()
    run_server(port=args.port, debug=args.debug)
