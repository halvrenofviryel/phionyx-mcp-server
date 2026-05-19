"""``phionyx-mcp`` command-line interface — Capability 8.

Subcommands:
    verify-chain --trace <id> [--turn <n>]
        Walk and verify the persisted chain for a trace. Exits 0 on
        valid chain, 1 on tamper/break, 2 on invocation error.

    head --trace <id>
        Print the current chain head hash for a trace.

    show --trace <id> [--turn <n>]
        Print the envelope at ``turn`` (or most recent if omitted) for
        a trace.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from .audit_chain import FilesystemEnvelopeStore, verify_chain


def cmd_verify_chain(args: argparse.Namespace) -> int:
    store = FilesystemEnvelopeStore()
    envelopes = list(store.iter_chain(args.trace))
    if args.turn is not None:
        envelopes = [e for e in envelopes if e["subject"]["turn_index"] <= args.turn]
    result = verify_chain(envelopes)
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


def cmd_head(args: argparse.Namespace) -> int:
    store = FilesystemEnvelopeStore()
    print(store.head(args.trace))
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    store = FilesystemEnvelopeStore()
    envelopes = list(store.iter_chain(args.trace))
    if not envelopes:
        print(json.dumps({"error": f"no envelopes for trace {args.trace!r}"}))
        return 1
    if args.turn is not None:
        match = [e for e in envelopes if e["subject"]["turn_index"] == args.turn]
        if not match:
            print(json.dumps({"error": f"no envelope at turn {args.turn}"}))
            return 1
        envelope = match[0]
    else:
        envelope = envelopes[-1]
    print(json.dumps(envelope, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phionyx-mcp",
        description="Phionyx MCP audit chain CLI (Capability 8).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    vp = sub.add_parser("verify-chain", help="Walk and verify a trace's envelope chain.")
    vp.add_argument("--trace", required=True, help="Trace identifier.")
    vp.add_argument("--turn", type=int, default=None, help="Optional max turn_index to verify up to.")
    vp.set_defaults(func=cmd_verify_chain)

    hp = sub.add_parser("head", help="Print the current chain head hash for a trace.")
    hp.add_argument("--trace", required=True)
    hp.set_defaults(func=cmd_head)

    sp = sub.add_parser("show", help="Print one envelope from a trace.")
    sp.add_argument("--trace", required=True)
    sp.add_argument("--turn", type=int, default=None, help="Turn index; default is most recent.")
    sp.set_defaults(func=cmd_show)

    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (FileNotFoundError, json.JSONDecodeError, RuntimeError) as e:
        print(json.dumps({"error": str(e), "type": type(e).__name__}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
