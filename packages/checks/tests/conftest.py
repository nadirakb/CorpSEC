from collections.abc import Callable

import httpx
import pytest

from corpsec_scanner import ScanOptions

Handler = Callable[[httpx.Request], httpx.Response]


@pytest.fixture
def mock_options() -> Callable[[Handler], ScanOptions]:
    """Scan options that route all HTTP through ``handler`` and skip DNS preflight."""

    def make(handler: Handler) -> ScanOptions:
        return ScanOptions(
            preflight=False,
            transport_factory=lambda verify: httpx.MockTransport(handler),
        )

    return make
