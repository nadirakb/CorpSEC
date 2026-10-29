import asyncio
import json
from pathlib import Path
from typing import ClassVar

import httpx
import jsonschema
import pytest

from corpsec_scanner import (
    Check,
    Evidence,
    Observation,
    ScanContext,
    ScanOptions,
    ScanStatus,
    Severity,
    Stage,
    run_scan,
)
from corpsec_scanner.engine import PlanError, plan
from corpsec_scanner.models import CheckRunStatus
from corpsec_scanner.netguard import NetConfig

SCHEMA = json.loads((Path(__file__).parents[3] / "schemas" / "finding.schema.json").read_text())


def options(**kw: object) -> ScanOptions:
    return ScanOptions(
        preflight=False,
        transport_factory=lambda verify: httpx.MockTransport(
            lambda req: httpx.Response(200, text="hi")
        ),
        **kw,  # type: ignore[arg-type]
    )


class Producer(Check):
    id = "TST-001"
    version = "1.0.0"
    stage = Stage.CONNECTION
    provides: ClassVar[frozenset[str]] = frozenset({"test.body"})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        r = await ctx.http.get(f"https://{ctx.target.host}/")
        ctx.set_fact("test.body", r.text)
        return []


class Consumer(Check):
    id = "TST-002"
    version = "1.0.0"
    stage = Stage.WEBSITE
    requires: ClassVar[frozenset[str]] = frozenset({"test.body"})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        body = ctx.facts.get("test.body")
        return [
            Observation(
                severity=Severity.LOW,
                host=ctx.target.host,
                evidence=Evidence(kind="http", observed=body, expected="something else"),
            )
        ]


class Boom(Check):
    id = "TST-003"
    version = "1.0.0"
    stage = Stage.EMAIL

    async def run(self, ctx: ScanContext) -> list[Observation]:
        raise RuntimeError("kaboom")


class Sleepy(Check):
    id = "TST-004"
    version = "1.0.0"
    stage = Stage.EMAIL

    async def run(self, ctx: ScanContext) -> list[Observation]:
        await asyncio.sleep(10)
        return []


class Sneaky(Check):
    id = "TST-005"
    version = "1.0.0"
    stage = Stage.EMAIL

    async def run(self, ctx: ScanContext) -> list[Observation]:
        ctx.set_fact("test.body", "overwritten")
        return []


def test_plan_orders_by_dependencies() -> None:
    layers = plan([Consumer(), Producer(), Boom()])
    assert [[c.id for c in layer] for layer in layers] == [["TST-001", "TST-003"], ["TST-002"]]


def test_plan_rejects_missing_provider() -> None:
    with pytest.raises(PlanError, match="no check provides"):
        plan([Consumer()])


def test_invalid_check_definition() -> None:
    with pytest.raises(TypeError, match="invalid check id"):

        class Bad(Check):
            id = "bad"
            version = "1.0.0"
            stage = Stage.EMAIL

            async def run(self, ctx: ScanContext) -> list[Observation]:
                return []


async def test_end_to_end_findings_match_schema() -> None:
    result = await run_scan("example.com", [Producer(), Consumer()], options=options())
    assert result.status == ScanStatus.COMPLETED
    assert [f.check_id for f in result.findings] == ["TST-002"]
    finding = result.findings[0]
    assert finding.evidence.observed == "hi"
    assert finding.scan_id == result.scan_id
    jsonschema.validate(json.loads(finding.model_dump_json()), SCHEMA)


async def test_check_error_makes_scan_partial() -> None:
    result = await run_scan("example.com", [Producer(), Boom()], options=options())
    assert result.status == ScanStatus.PARTIAL
    run = next(r for r in result.check_runs if r.check_id == "TST-003")
    assert run.status == CheckRunStatus.ERROR
    assert "kaboom" in (run.detail or "")


async def test_undeclared_fact_write_is_an_error() -> None:
    result = await run_scan("example.com", [Producer(), Sneaky()], options=options())
    run = next(r for r in result.check_runs if r.check_id == "TST-005")
    assert run.status == CheckRunStatus.ERROR


async def test_consumer_skipped_when_fact_missing() -> None:
    class SilentProducer(Producer):
        async def run(self, ctx: ScanContext) -> list[Observation]:
            return []

    result = await run_scan("example.com", [SilentProducer(), Consumer()], options=options())
    run = next(r for r in result.check_runs if r.check_id == "TST-002")
    assert run.status == CheckRunStatus.SKIPPED
    assert result.status == ScanStatus.COMPLETED


async def test_per_check_timeout() -> None:
    result = await run_scan(
        "example.com", [Producer(), Sleepy()], options=options(per_check_timeout=0.05)
    )
    run = next(r for r in result.check_runs if r.check_id == "TST-004")
    assert run.status == CheckRunStatus.TIMEOUT
    assert result.status == ScanStatus.PARTIAL


async def test_scan_budget_marks_unfinished_checks() -> None:
    result = await run_scan(
        "example.com", [Sleepy(), Producer(), Consumer()], options=options(budget_seconds=0.1)
    )
    assert result.status == ScanStatus.PARTIAL
    statuses = {r.check_id: r.status for r in result.check_runs}
    assert statuses["TST-004"] == CheckRunStatus.TIMEOUT
    assert statuses["TST-002"] == CheckRunStatus.TIMEOUT


async def test_preflight_refuses_private_target() -> None:
    async def fake_resolve(host: str, port: int = 443) -> list[str]:
        return ["93.184.215.14", "10.0.0.5"]

    options = ScanOptions(net=NetConfig(resolver=fake_resolve))
    result = await run_scan("example.com", [Producer()], options=options)
    assert result.status == ScanStatus.FAILED
    assert result.error == "CorpSEC can only check public websites."
    assert result.check_runs == []


def test_plan_orders_optional_uses() -> None:
    class OptionalConsumer(Consumer):
        id = "TST-006"
        requires: ClassVar[frozenset[str]] = frozenset()
        uses: ClassVar[frozenset[str]] = frozenset({"test.body"})

    layers = plan([OptionalConsumer(), Producer()])
    assert [[c.id for c in layer] for layer in layers] == [["TST-001"], ["TST-006"]]
    assert plan([OptionalConsumer()])  # no producer is fine for optional facts
