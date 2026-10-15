# tiny-headers-redact

> Framework-agnostic middleware that redacts credentials from HTTP headers.
> One file, ~200 LOC, zero new dependencies beyond `tiny-secret-mask>=0.5.0`.

## Why

OpenClaw agents and services forward HTTP requests to internal services, proxy
them, log them, and emit them as trace spans. A header like

    Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig

can carry a credential by accident. SOUL.md mandates "Private things stay
private. Period." so we redact by default at the middleware layer so the
redacted form is what every downstream consumer sees.

This package is the answer to "I want header redaction but I do not use
`tiny-router`." It mirrors the `tiny-route-redact` shape: a single
file, WSGI + ASGI middlewares, a counter object, and a single-function
`redact_headers(headers)` that does the work in one call.

## Install

```
pip install tiny-headers-redact
```

## Public API

- `redact_headers(headers) -> dict` — returns a NEW dict with credential-
  bearing header values replaced. Falls back to a shallow copy if
  `tiny-secret-mask >= 0.5.0` is not installed.
- `header_redactor_middleware(get_response)` — WSGI-style middleware that
  rewrites request headers before the wrapped app sees them.
- `header_redactor_asgi_middleware(app)` — ASGI-style middleware that
  rewrites the `headers` scope key.
- `HeaderStats` — counter object (`headers_seen`, `redactions`,
  `last_redacted_header`) for `/metrics` endpoints.

## Quick start

```python
from tiny_headers_redact import redact_headers

redact_headers({"Authorization": "Bearer xyz", "X-Request-Id": "abc"})
# {'Authorization': '[REDACTED:authorization]', 'X-Request-Id': 'abc'}
```

```python
from tiny_headers_redact import header_redactor_middleware, HeaderStats

stats = HeaderStats()
app = header_redactor_middleware(my_app, stats=stats)
# Every request now has its credential headers scrubbed before my_app sees it.
```

## Default header catalogue (16 rules)

The default rule set is owned by `tiny-secret-mask` v0.5.0+. Adding a
new rule is a one-PR change to `tiny_secret_mask.HEADER_REDACT_RULES`,
not this package.

| Severity | Header name |
|----------|-------------|
| critical | Authorization |
| critical | Proxy-Authorization |
| critical | X-API-Key |
| critical | X-Auth-Token |
| critical | X-Hub-Token |
| critical | X-GitHub-Token |
| critical | X-Slack-Token |
| critical | X-Shopify-Access-Token |
| critical | X-AWS-Security-Token |
| high | Cookie |
| high | Set-Cookie |
| high | X-CSRF-Token |
| high | X-Hub-Signature / X-Hub-Signature-256 |
| high | Stripe-Signature |
| high | X-AWS-Signature |
| high | Bearer |

## Framework adapters

| Framework | Adapter |
|-----------|---------|
| `tiny-router` v0.7.x | Use `tiny_router_redact_headers.redact_headers_middleware()` |
| FastAPI | Wrap with `app.middleware("http")` adapter (see `llms.txt`) |
| Django | Wrap with `MiddlewareMixin` adapter (see `llms.txt`) |
| Raw WSGI | `header_redactor_middleware(app)` |
| Raw ASGI | `header_redactor_asgi_middleware(app)` |

## License

MIT

