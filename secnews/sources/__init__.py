"""Source ingesters for secnews."""

from __future__ import annotations

from urllib.parse import urlparse

import requests as _requests

# Maximum redirects allowed for any outbound HTTP request.
# Prevents redirect-loop DoS and limits SSRF via open redirects.
_MAX_REDIRECTS = 5


def http_get(url: str, **kwargs) -> _requests.Response:
    """
    Drop-in wrapper around requests.get() with a hard redirect cap.
    All source ingesters should use this instead of requests.get() directly.
    """
    kwargs.setdefault("allow_redirects", True)
    with _requests.Session() as s:
        s.max_redirects = _MAX_REDIRECTS
        return s.get(url, **kwargs)


def _safe_url(url: str) -> str | None:
    """Return the URL if it has an allowed scheme (http/https), else None."""
    if not url:
        return None
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return None
        if not parsed.netloc:
            return None
    except Exception:
        return None
    return url
