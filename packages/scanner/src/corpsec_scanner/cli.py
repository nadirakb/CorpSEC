"""Developer CLI: ``corpsec-scan example.com`` prints the scan result as JSON."""

from __future__ import annotations

import argparse
import asyncio
import sys

from corpsec_scanner.check import load_checks
from corpsec_scanner.engine import ProgressEvent, run_scan
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
    args = parser.parse_args(argv)
    try:
        target = normalize_target(args.target)
    except InvalidTargetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    result = asyncio.run(run_scan(target, load_checks(), on_progress=_progress))
    print(result.model_dump_json(indent=2))
    return 0 if result.status != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
