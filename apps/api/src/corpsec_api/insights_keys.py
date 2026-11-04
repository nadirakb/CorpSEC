"""Keys that let analytics count a site once without storing its name."""

from __future__ import annotations

import hashlib
import hmac


def site_key(secret: str, domain: str) -> str:
    """Stable, non-reversible id for a domain (keyed, so names can't be guessed back)."""
    return hmac.new(secret.encode(), domain.lower().encode(), hashlib.sha256).hexdigest()[:16]
