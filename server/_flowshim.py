"""Transport-neutral request/response for the game server.

`_pserver.py` was written against mitmproxy's `HTTPFlow`, but the game logic
only touches a handful of fields.  This module provides those under a plain
HTTP(S) server (`server/app.py`) and a `make()` that returns a real mitmproxy
`Response` when mitmproxy is importable — so the same handlers run both under
the standalone server and under the sweep/RE capture addon
(`server/re/_capture_addon.py`).

Inventoried surface (see `_pserver.py`): `request.host / method / path /
raw_content / headers / query`, `response` assignment, `response.content`,
`metadata`, `client_conn.peername`, `error.msg`.
"""
from __future__ import annotations

import urllib.parse

try:  # mitmproxy present -> stay a real addon
    from mitmproxy import http as _http
except Exception:  # standalone server: no mitmproxy installed
    _http = None


class Headers:
    """Case-insensitive header view with mitmproxy's `.get`."""

    def __init__(self, items=()):
        self._d = {}
        pairs = items.items() if hasattr(items, 'items') else (items or ())
        for k, v in pairs:
            self._d[str(k).lower()] = v

    def get(self, key, default=None):
        return self._d.get(str(key).lower(), default)

    def __getitem__(self, key):
        return self._d[str(key).lower()]

    def __contains__(self, key):
        return str(key).lower() in self._d

    def items(self):
        return self._d.items()


class Query:
    """First-value view of a query string, like mitmproxy's MultiDictView."""

    def __init__(self, qs=''):
        self._q = {k: v[0] for k, v in
                   urllib.parse.parse_qs(qs, keep_blank_values=True).items()}

    def get(self, key, default=None):
        return self._q.get(key, default)

    def __contains__(self, key):
        return key in self._q


class Request:
    def __init__(self, host, method, path, headers=None, body=b''):
        self.host = host
        self.pretty_host = host
        self.method = method
        self.path = path                       # includes the query string
        self.raw_content = body or b''
        self.content = body or b''
        self.headers = headers if isinstance(headers, Headers) else Headers(headers or ())
        self.query = Query(urllib.parse.urlsplit(path).query)


class Response:
    """Used only when mitmproxy is absent; mimics the fields `app.py` reads."""

    def __init__(self, status_code=200, content=b'', headers=None):
        self.status_code = status_code
        self.content = content if isinstance(content, (bytes, bytearray)) \
            else bytes(content)
        self.headers = headers if isinstance(headers, Headers) else Headers(headers or ())

    @classmethod
    def make(cls, status, body=b'', headers=None):
        return cls(status, body, headers)


class Conn:
    def __init__(self, addr=''):
        self.peername = (addr, 0) if addr else None


class Error:
    def __init__(self, msg=''):
        self.msg = msg


class Flow:
    def __init__(self, request, conn=None):
        self.request = request
        self.response = None
        self.metadata = {}
        self.error = None
        self.client_conn = conn or Conn()


def make(status, body=b'', headers=None):
    """A response usable by whichever transport is active."""
    if _http is not None:
        return _http.Response.make(status, body, headers or {})
    return Response.make(status, body, headers)


def status_of(resp):
    return getattr(resp, 'status_code', 200)


def body_of(resp):
    c = getattr(resp, 'content', b'') or b''
    return bytes(c)


def headers_of(resp):
    h = getattr(resp, 'headers', None)
    if h is None:
        return {}
    if hasattr(h, 'items'):
        return {str(k): str(v) for k, v in h.items()}
    return dict(h)
