"""tiny_headers_redact - middleware that redacts credentials from HTTP headers.

The smallest reliable way to keep credential-shaped HTTP headers
(Authorization, Cookie, Set-Cookie, X-API-Key, X-Auth-Token, Stripe-Signature,
etc.) out of logs, error reports, observability spans, and downstream services.
Pure Python standard library - no regex hacks, no compiled extensions.

Why?
----
OpenClaw agents and services forward HTTP requests to internal services,
proxy them, log them, and emit them as trace spans. A header like

    Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig

can carry a credential by accident. SOUL.md mandates "Private things stay
private. Period." so we redact by default at the middleware layer so the
redacted form is what every downstream consumer sees.

Use cases
---------
- Standalone middleware for any WSGI/ASGI-like framework that calls
  ``redact_headers(headers)`` or uses the bundled ``header_redactor_middleware``.
- Use the underlying ``mask_headers()`` from ``tiny_secret_mask`` v0.5.0+
  directly for the same effect with a single function call.
- Layered defence: combine with ``tiny_log`` redaction so even an unredacted
  header that slips through is sanitised before persistence.

Public API
----------
- ``redact_headers(headers) -> dict`` - convenience wrapper that returns
  a NEW dict with credential-bearing header values replaced. Equivalent to
  ``tiny_secret_mask.mask_headers(headers)``.
- ``header_redactor_middleware(get_response)`` - WSGI-style middleware that
  rewrites request headers before the wrapped app sees them. Compatible
  with ``tiny_router`` v0.7.x, FastAPI, and Django.
- ``header_redactor_asgi_middleware(app)`` - ASGI-style middleware that
  rewrites the ``headers`` scope key. Returns a coroutine callable.
- ``HeaderStats`` - counter object (``headers_seen``, ``redactions``,
  ``last_redacted_header``) useful for ``/metrics`` endpoints.

Quick start
-----------
>>> from tiny_headers_redact import redact_headers
>>> redact_headers({"Authorization": "Bearer xyz", "X-Request-Id": "abc"})
{'Authorization': '[REDACTED:authorization]', 'X-Request-Id': 'abc'}

>>> from tiny_headers_redact import header_redactor_middleware, HeaderStats
>>> stats = HeaderStats()
>>> app = header_redactor_middleware(my_app, stats=stats)
>>> # Every request now has its credential headers scrubbed before my_app sees it.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, Optional


__version__ = "0.1.0"


def _resolve_mask():
    """Resolve the header redaction function from tiny_secret_mask v0.5.0+."""
    try:
        from tiny_secret_mask import mask_headers
        return mask_headers
    except ImportError:
        return None
    except Exception:
        return None


_MASK = _resolve_mask()


class HeaderStats:
    """Lightweight counter object for observability."""

    __slots__ = ("headers_seen", "redactions", "last_redacted_header")

    def __init__(self):
        self.headers_seen = 0
        self.redactions = 0
        self.last_redacted_header = None

    def observe(self, headers, redacted):
        """Record a (original, redacted) header pair."""
        self.headers_seen += len(headers) if headers else 0
        for k, red in (redacted or {}).items():
            if headers.get(k) != red:
                self.redactions += 1
                self.last_redacted_header = k

    def as_dict(self):
        return {
            "headers_seen": self.headers_seen,
            "redactions": self.redactions,
            "last_redacted_header": self.last_redacted_header,
        }


def redact_headers(headers):
    """Redact credential-shaped header values in headers.

    Returns a NEW dict. Falls back to a shallow copy if tiny_secret_mask
    >= 0.5.0 is not installed.
    """
    if headers is None:
        return {}
    if _MASK is None:
        # A security library that quietly stops redacting is worse than one
        # that is not installed at all: the caller believes headers are
        # scrubbed while credentials flow through untouched. Fail loudly
        # instead. Use redact_headers_passthrough() for a deliberate no-op.
        raise RuntimeError(
            "tiny_secret_mask >= 0.5.0 is required for header redaction, "
            "but it could not be imported. Install it, or call "
            "redact_headers_passthrough() to opt out explicitly."
        )
    return _MASK(dict(headers))


def redact_headers_passthrough(headers):
    """Return a shallow copy of headers with NO redaction applied.

    This is the explicit opt-out for callers that cannot install
    tiny_secret_mask. Prefer redact_headers(), which raises rather than
    silently passing credentials through.
    """
    if headers is None:
        return {}
    return dict(headers)


# ---------- Middleware ----------


def header_redactor_middleware(get_response, *, stats=None, on_redact=None):
    """WSGI-style middleware that rewrites request headers."""
    s = stats
    cb = on_redact

    def _apply_redaction(request):
        if isinstance(request, dict):
            original = dict(request.get("headers") or {})
        else:
            original = dict(getattr(request, "headers", {}) or {})
        redacted = redact_headers(original)
        if redacted != original:
            if isinstance(request, dict):
                request["headers"] = redacted
            else:
                try:
                    request.headers = redacted
                except Exception:
                    pass
            if s is not None:
                s.observe(original, redacted)
            if cb is not None:
                try:
                    cb(original, redacted)
                except Exception:
                    pass
        elif s is not None:
            s.observe(original, redacted)

    def _middleware(request):
        _apply_redaction(request)
        return get_response(request)

    _middleware._is_header_redactor = True  # type: ignore
    return _middleware


def header_redactor_asgi_middleware(app, *, stats=None):
    """ASGI-style middleware that rewrites the headers scope key."""
    s = stats

    async def _middleware(scope, receive, send):
        if scope.get("type") == "http":
            raw_headers = scope.get("headers") or []
            original = {}
            for k, v in raw_headers:
                try:
                    original[k.decode("latin-1")] = v.decode("latin-1")
                except Exception:
                    pass
            redacted = redact_headers(original)
            if redacted != original:
                new_headers = []
                for k, v in raw_headers:
                    key = k.decode("latin-1") if isinstance(k, bytes) else k
                    if key in redacted:
                        new_headers.append((k, redacted[key].encode("latin-1")))
                    else:
                        new_headers.append((k, v))
                new_scope = dict(scope)
                new_scope["headers"] = new_headers
                if s is not None:
                    s.observe(original, redacted)
                await app(new_scope, receive, send)
                return
            if s is not None:
                s.observe(original, redacted)
        await app(scope, receive, send)

    return _middleware


__all__ = [
    "redact_headers",
    "header_redactor_middleware",
    "header_redactor_asgi_middleware",
    "HeaderStats",
    "__version__",
]
