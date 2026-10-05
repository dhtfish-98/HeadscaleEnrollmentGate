"""Trusted-operator CLI. Capabilities and auth keys are emitted only once."""

import argparse
import json
from pathlib import Path
import sys

from .gate import EnrollmentGate, GateError, HeadscaleCLI


def main() -> int:
    parser = argparse.ArgumentParser(prog="headscale-enrollment-gate")
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--headscale-bin", type=Path, required=True)
    parser.add_argument("--headscale-config", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "redeem"):
        command = sub.add_parser(name)
        command.add_argument("--audience", required=True)
        command.add_argument("--mode", choices=("personal", "tagged"), required=True)
        command.add_argument("--user-id", required=True)
        command.add_argument("--tag", action="append", default=[])
        if name == "plan":
            command.add_argument("--ttl", type=int, required=True)
    status = sub.add_parser("status")
    status.add_argument("--grant-id", required=True)
    args = parser.parse_args()
    try:
        gate = EnrollmentGate(
            args.db, args.policy, HeadscaleCLI(args.headscale_bin, args.headscale_config)
        )
        if args.command == "plan":
            grant_id, token, deadline = gate.plan(
                args.audience, args.mode, args.user_id, args.tag, args.ttl
            )
            print(json.dumps({"grant_id": grant_id, "token": token,
                              "expires_at": deadline}))
        elif args.command == "redeem":
            token = sys.stdin.readline().strip()
            minted = gate.redeem(
                token, args.audience, args.mode, args.user_id, args.tag
            )
            print(json.dumps({"key": minted.secret, "key_id": minted.key_id,
                              "expires_at": minted.expires_at}))
        else:
            print(json.dumps(gate.status(args.grant_id), sort_keys=True))
        return 0
    except GateError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
