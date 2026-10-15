# Changelog

All notable changes to tiny-headers-redact are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-10-15

### Added
- **Initial release.** Framework-agnostic middleware that redacts
  credentials from HTTP headers.
- `redact_headers(headers) -> dict` - returns a NEW dict with credential-
  bearing header values replaced. Falls back to a shallow copy if
  `tiny-secret-mask >= 0.5.0` is not installed.
- `header_redactor_middleware(get_response)` - WSGI-style middleware that
  rewrites request headers before the wrapped app sees them.
- `header_redactor_asgi_middleware(app)` - ASGI-style middleware that
  rewrites the `headers` scope key.
- `HeaderStats` - counter object (`headers_seen`, `redactions`,
  `last_redacted_header`) for `/metrics` endpoints.
- Default rule set covers 16 patterns: Authorization, Proxy-Authorization,
  Cookie, Set-Cookie, X-API-Key, X-Auth-Token, X-CSRF-Token, X-Hub-Signature,
  X-Hub-Signature-256, X-Hub-Token, Stripe-Signature, X-GitHub-Token,
  X-Slack-Token, X-Shopify-Access-Token, X-AWS-Signature, X-AWS-Security-Token.
- 19 tests in `tests/test_tiny_headers_redact.py`. All pass.
- MIT license, single file, ~200 LOC.

### Notes
- The default rule set is owned by `tiny-secret-mask` v0.5.0+, NOT by
  this package. Adding a new header rule is a one-PR change to
  `tiny_secret_mask.HEADER_REDACT_RULES`, not this file.
- This package is the header-redaction equivalent of `tiny-route-redact`
  (path redaction). Together they form the credential-leak loop at the
  HTTP boundary.
- For framework-native integration, use the sidecar modules:
  - `tiny_router_redact_headers` for tiny-router v0.7.x.
  - `fastapi-header-redact` adapters (not yet published).
  - `django-header-redact` adapters (not yet published).

