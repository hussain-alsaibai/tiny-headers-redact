"""Regression test: a missing dependency must not silently disable redaction.

Before this test, redact_headers() returned a shallow copy of the headers
when tiny_secret_mask could not be imported. A caller would then believe
the headers were scrubbed while the credentials passed through untouched
-- the worst possible failure mode for a security library.

redact_headers() now raises, and redact_headers_passthrough() is the
explicit opt-out.
"""

from __future__ import annotations

import pytest

import tiny_headers_redact


def test_redact_headers_raises_when_mask_is_unavailable(monkeypatch):
    monkeypatch.setattr(tiny_headers_redact, "_MASK", None, raising=False)

    with pytest.raises(RuntimeError, match="tiny_secret_mask"):
        tiny_headers_redact.redact_headers({"Authorization": "Bearer abc"})


def test_passthrough_is_the_explicit_opt_out(monkeypatch):
    monkeypatch.setattr(tiny_headers_redact, "_MASK", None, raising=False)

    headers = {"Authorization": "Bearer abc", "X-Request-Id": "abc"}
    out = tiny_headers_redact.redact_headers_passthrough(headers)

    # Deliberately NOT redacted, and clearly so.
    assert out["Authorization"] == "Bearer abc"
    assert out is not headers


def test_redact_headers_still_redacts_when_available():
    out = tiny_headers_redact.redact_headers(
        {"Authorization": "Bearer abc", "X-Request-Id": "abc"}
    )
    assert out["Authorization"] != "Bearer abc"
    assert out["X-Request-Id"] == "abc"
