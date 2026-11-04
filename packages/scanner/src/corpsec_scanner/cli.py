"""Developer CLI: ``corpsec-scan example.com`` prints the scan result as JSON."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

from corpsec_scanner.check import load_checks
from corpsec_scanner.engine import ProgressEvent, ScanOptions, run_scan
from corpsec_scanner.intel import load_snapshot
from corpsec_scanner.target import InvalidTargetError, normalize_target


async def _progress(event: ProgressEvent) -> None:
    print(
        f"[{event.completed}/{event.total}] {event.check_id} {event.status.value}"
        f" ({event.findings} findings)",
        file=sys.stderr,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="corpsec-scan", description=__doc__)
    parser.add_argument("target", help="website or domain, e.g. example.com")
    parser.add_argument(
        "--intel",
        default=os.environ.get("CORPSEC_INTEL_PATH"),
        help="intel snapshot from corpsec-intel-sync (default: $CORPSEC_INTEL_PATH)",
    )
    parser.add_argument(
        "--config",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="check setting, e.g. internetdb=on or spamhaus_dqs_key=... (repeatable)",
    )
    args = parser.parse_args(argv)
    config = dict(item.split("=", 1) for item in args.config if "=" in item)
    try:
        target = normalize_target(args.target)
    except InvalidTargetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    options = ScanOptions(intel=load_snapshot(args.intel), check_config=config)
    if options.intel.empty:
        print("note: no intel snapshot; software vulnerability checks are skipped", file=sys.stderr)
    result = asyncio.run(run_scan(target, load_checks(), options=options, on_progress=_progress))
    print(result.model_dump_json(indent=2))
    return 0 if result.status != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
