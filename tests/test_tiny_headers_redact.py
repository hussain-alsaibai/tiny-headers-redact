"""Tests for tiny_headers_redact."""

import asyncio
import unittest
from types import SimpleNamespace

import tiny_headers_redact as m


def make_req(headers=None):
    return SimpleNamespace(
        method="GET",
        path="/",
        headers=headers if headers is not None else {},
        body=b"",
    )


def call_pass_through(req):
    return b"ok"


class TestVersion(unittest.TestCase):
    def test_version(self):
        self.assertEqual(m.__version__, "0.1.0")


class TestRedactHeaders(unittest.TestCase):
    def test_authorization_redacted(self):
        out = m.redact_headers({"Authorization": "Bearer xyz"})
        self.assertEqual(out["Authorization"], "[REDACTED:authorization]")

    def test_cookie_redacted(self):
        out = m.redact_headers({"Cookie": "session=abc"})
        self.assertEqual(out["Cookie"], "[REDACTED:cookie]")

    def test_x_api_key_redacted(self):
        out = m.redact_headers({"X-API-Key": "secret"})
        self.assertEqual(out["X-API-Key"], "[REDACTED:x_api_key]")

    def test_non_sensitive_preserved(self):
        out = m.redact_headers({"X-Request-Id": "550e8400-e29b-41d4-a716-446655440000"})
        self.assertEqual(out["X-Request-Id"], "550e8400-e29b-41d4-a716-446655440000")

    def test_content_type_preserved(self):
        out = m.redact_headers({"Content-Type": "application/json"})
        self.assertEqual(out["Content-Type"], "application/json")

    def test_user_agent_preserved(self):
        out = m.redact_headers({"User-Agent": "Mozilla/5.0"})
        self.assertEqual(out["User-Agent"], "Mozilla/5.0")

    def test_input_not_mutated(self):
        original = {"Authorization": "Bearer xyz"}
        m.redact_headers(original)
        self.assertEqual(original["Authorization"], "Bearer xyz")

    def test_none_input(self):
        self.assertEqual(m.redact_headers(None), {})

    def test_empty_input(self):
        self.assertEqual(m.redact_headers({}), {})

    def test_idempotent(self):
        once = m.redact_headers({"Authorization": "Bearer xyz"})
        twice = m.redact_headers(once)
        self.assertEqual(once, twice)


class TestHeaderStats(unittest.TestCase):
    def test_default(self):
        s = m.HeaderStats()
        self.assertEqual(s.headers_seen, 0)
        self.assertEqual(s.redactions, 0)
        self.assertIsNone(s.last_redacted_header)

    def test_observe_redacted(self):
        s = m.HeaderStats()
        s.observe({"Authorization": "Bearer xyz"}, {"Authorization": "[REDACTED]"})
        self.assertEqual(s.redactions, 1)
        self.assertEqual(s.headers_seen, 1)
        self.assertEqual(s.last_redacted_header, "Authorization")

    def test_observe_unchanged(self):
        s = m.HeaderStats()
        s.observe({"X-Request-Id": "abc"}, {"X-Request-Id": "abc"})
        self.assertEqual(s.redactions, 0)
        self.assertEqual(s.headers_seen, 1)
        self.assertIsNone(s.last_redacted_header)

    def test_as_dict(self):
        s = m.HeaderStats()
        s.headers_seen = 5
        s.redactions = 1
        s.last_redacted_header = "Authorization"
        d = s.as_dict()
        self.assertEqual(d["headers_seen"], 5)
        self.assertEqual(d["redactions"], 1)
        self.assertEqual(d["last_redacted_header"], "Authorization")


class TestWsgiiMiddleware(unittest.TestCase):
    def test_object_request(self):
        req = make_req({"Authorization": "Bearer xyz"})
        app = m.header_redactor_middleware(call_pass_through)
        result = app(req)
        self.assertEqual(req.headers["Authorization"], "[REDACTED:authorization]")
        self.assertEqual(result, b"ok")

    def test_dict_request(self):
        req = {"headers": {"Authorization": "Bearer xyz"}, "path": "/"}
        app = m.header_redactor_middleware(call_pass_through)
        result = app(req)
        self.assertEqual(req["headers"]["Authorization"], "[REDACTED:authorization]")

    def test_stats_increment(self):
        stats = m.HeaderStats()
        req = make_req({"Authorization": "Bearer xyz", "X-API-Key": "secret"})
        app = m.header_redactor_middleware(call_pass_through, stats=stats)
        app(req)
        self.assertGreater(stats.headers_seen, 0)
        self.assertGreaterEqual(stats.redactions, 2)

    def test_on_redact_callback(self):
        captured = []
        def cb(orig, red):
            captured.append((orig, red))
        req = make_req({"Authorization": "Bearer xyz"})
        app = m.header_redactor_middleware(call_pass_through, on_redact=cb)
        app(req)
        self.assertEqual(len(captured), 1)

    def test_idempotent(self):
        req = make_req({"Authorization": "Bearer xyz"})
        app = m.header_redactor_middleware(call_pass_through)
        app(req)
        once = dict(req.headers)
        app(req)
        self.assertEqual(req.headers, once)

    def test_marked_as_redactor(self):
        app = m.header_redactor_middleware(call_pass_through)
        self.assertTrue(getattr(app, "_is_header_redactor", False))


class TestAsgiMiddleware(unittest.TestCase):
    def test_asgi_redacts(self):
        async def run():
            scope = {
                "type": "http",
                "headers": [
                    (b"authorization", b"Bearer xyz"),
                    (b"x-request-id", b"abc-123"),
                    (b"content-type", b"application/json"),
                ],
            }
            captured = {}

            async def app(s, receive, send):
                captured["scope"] = s

            mw = m.header_redactor_asgi_middleware(app)
            await mw(scope, lambda: None, lambda msg: None)
            new_scope = captured["scope"]
            new_headers = {k.decode(): v.decode() for k, v in new_scope["headers"]}
            self.assertEqual(new_headers["authorization"], "[REDACTED:authorization]")
            self.assertEqual(new_headers["x-request-id"], "abc-123")
            self.assertEqual(new_headers["content-type"], "application/json")

        asyncio.run(run())

    def test_asgi_no_redactions(self):
        async def run():
            scope = {
                "type": "http",
                "headers": [(b"x-request-id", b"abc")],
            }
            called = []

            async def app(s, receive, send):
                called.append(s)

            mw = m.header_redactor_asgi_middleware(app)
            await mw(scope, lambda: None, lambda msg: None)
            self.assertEqual(len(called), 1)

        asyncio.run(run())

    def test_asgi_non_http_scope_passthrough(self):
        async def run():
            scope = {"type": "websocket", "headers": []}
            called = []

            async def app(s, receive, send):
                called.append(s)

            mw = m.header_redactor_asgi_middleware(app)
            await mw(scope, lambda: None, lambda msg: None)
            self.assertEqual(len(called), 1)

        asyncio.run(run())


class TestInitExports(unittest.TestCase):
    def test_init_imports(self):
        import tiny_headers_redact as pkg
        self.assertTrue(hasattr(pkg, "redact_headers"))
        self.assertTrue(hasattr(pkg, "HeaderStats"))
        self.assertTrue(hasattr(pkg, "header_redactor_middleware"))
        self.assertTrue(hasattr(pkg, "header_redactor_asgi_middleware"))
        self.assertTrue(hasattr(pkg, "__version__"))


if __name__ == "__main__":
    unittest.main()

