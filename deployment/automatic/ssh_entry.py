#!/usr/bin/env python3
"""A forced SSH command; each authorized key is bound to one application."""

import os
import re
import sys


def parse_command(target, command):
    if target not in {"web", "backend", "marketing"}:
        raise ValueError("Unknown deployment target")
    match = re.fullmatch(r"deploy ([0-9a-f]{40}) ([0-9a-f]{64})", command)
    if not match:
        raise ValueError("Only a commit-pinned deployment is permitted")
    return ["/usr/bin/sudo", "-n", "/usr/local/sbin/padlupp-deploy", target, *match.groups()]


if __name__ == "__main__":
    try:
        args = parse_command(sys.argv[1], os.environ.get("SSH_ORIGINAL_COMMAND", ""))
    except (ValueError, IndexError) as error:
        raise SystemExit(str(error))
    os.execv(args[0], args)
