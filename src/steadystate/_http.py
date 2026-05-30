"""Internal HTTP helper: every outbound request goes through one audited urlopen.

steadystate opens URLs the operator configures -- chat webhooks, a Prometheus/Grafana base,
the ArgoCD/Rancher APIs, an LLM endpoint. Routing them all through one place lets us enforce a
single invariant: we only ever speak http(s). That rejects ``file://``, ``ftp://``, ``gopher://``
and the other schemes ``urllib`` would otherwise honor (the local-file / SSRF surface), and it
fails fast with a clear error on a mistyped URL -- instead of silently reading a local file.
"""

from __future__ import annotations

import urllib.request
from typing import Any
from urllib.parse import urlparse

_ALLOWED_SCHEMES = frozenset({"http", "https"})


def _url_of(target: str | urllib.request.Request) -> str:
    return target.full_url if isinstance(target, urllib.request.Request) else target


def safe_urlopen(target: str | urllib.request.Request, *, timeout: float | None = None) -> Any:
    """``urllib.request.urlopen`` restricted to http(s).

    Raises ``ValueError`` for any other scheme (or a schemeless URL) *before* a socket opens.
    Callers keep their own timeout + error handling; this only narrows *which* URLs may open.
    """
    scheme = urlparse(_url_of(target)).scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f"refusing to open a non-http(s) URL (scheme: {scheme or 'none'!r})")
    # B310: scheme is allow-listed to http(s) immediately above, so this is the audited gate.
    return urllib.request.urlopen(target, timeout=timeout)  # nosec B310
