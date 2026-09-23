#!/usr/bin/env python3
import argparse

from mimoe_port_check.agent import main

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="mimoe-port-check -- local security check agent")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print the model's raw tool-choice output for every routing decision.",
    )
    args = parser.parse_args()
    main(debug=args.debug)
