"""HTTP transport hardening tests (DD-242 / access-policy).

The blade-mcp transport policy forbids an http-enabled blade from serving
unauthenticated or on a non-loopback interface. ``_require_secure_http`` is the
gate; these tests pin both invariants plus the bearer middleware behaviour.
"""

from __future__ import annotations

import json

import pytest

from controld_blade_mcp import auth
from controld_blade_mcp.server import _require_secure_http


class TestHttpTransportGate:
    def test_refuses_http_without_token(self) -> None:
        with pytest.raises(SystemExit) as exc:
            _require_secure_http("127.0.0.1", None)
        assert "without auth" in str(exc.value)

    def test_refuses_non_loopback_bind(self) -> None:
        with pytest.raises(SystemExit) as exc:
            _require_secure_http("0.0.0.0", "a-real-token")  # noqa: S104 — asserting it's refused
        assert "non-loopback" in str(exc.value)

    @pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
    def test_allows_loopback_with_token(self, host: str) -> None:
        # Returns None (does not raise) when both invariants hold.
        assert _require_secure_http(host, "a-real-token") is None


class TestBearerToken:
    def setup_method(self) -> None:
        auth._BEARER_TOKEN = None
        auth._BEARER_CHECKED = False

    def teardown_method(self) -> None:
        auth._BEARER_TOKEN = None
        auth._BEARER_CHECKED = False

    def test_unset_token_is_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CONTROLD_MCP_API_TOKEN", raising=False)
        assert auth.get_bearer_token() is None

    def test_blank_token_is_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CONTROLD_MCP_API_TOKEN", "   ")
        assert auth.get_bearer_token() is None

    def test_set_token_is_returned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CONTROLD_MCP_API_TOKEN", "sekret")
        assert auth.get_bearer_token() == "sekret"


class _Sink:
    """Capture ASGI send() events."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    async def __call__(self, event: dict) -> None:
        self.events.append(event)


async def _noop_app(scope, receive, send) -> None:  # type: ignore[no-untyped-def]
    await send({"type": "http.response.start", "status": 200, "headers": []})


class TestBearerMiddleware:
    def setup_method(self) -> None:
        auth._BEARER_TOKEN = None
        auth._BEARER_CHECKED = False

    def teardown_method(self) -> None:
        auth._BEARER_TOKEN = None
        auth._BEARER_CHECKED = False

    async def test_rejects_missing_header(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CONTROLD_MCP_API_TOKEN", "sekret")
        mw = auth.BearerAuthMiddleware(_noop_app)
        sink = _Sink()
        await mw({"type": "http", "headers": []}, None, sink)
        assert sink.events[0]["status"] == 401
        assert json.loads(sink.events[1]["body"]) == {"error": "Unauthorized"}

    async def test_rejects_wrong_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CONTROLD_MCP_API_TOKEN", "sekret")
        mw = auth.BearerAuthMiddleware(_noop_app)
        sink = _Sink()
        await mw({"type": "http", "headers": [(b"authorization", b"Bearer nope")]}, None, sink)
        assert sink.events[0]["status"] == 401

    async def test_accepts_valid_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CONTROLD_MCP_API_TOKEN", "sekret")
        mw = auth.BearerAuthMiddleware(_noop_app)
        sink = _Sink()
        await mw({"type": "http", "headers": [(b"authorization", b"Bearer sekret")]}, None, sink)
        assert sink.events[0]["status"] == 200
