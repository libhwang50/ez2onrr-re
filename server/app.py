#!/usr/bin/env python3
"""Standalone EZ2ON private server — no mitmproxy required.

The game logic lives in `_pserver.py` (transport-neutral via `_flowshim.py`);
this file is just HTTP(S) transport plus config.  It answers the game's three
hostnames, selected by the `X-EZ2-Host` header (the client-side relay sets it)
or, failing that, the request `Host`.

    # local / behind a reverse proxy (plain HTTP)
    python server/app.py --host 127.0.0.1 --port 8081

    # public, direct TLS
    python server/app.py --host 0.0.0.0 --port 8443 \
        --cert /etc/letsencrypt/live/ez2.example/fullchain.pem \
        --key  /etc/letsencrypt/live/ez2.example/privkey.pem

An ASGI callable `app` is also exported for uvicorn/hypercorn:

    uvicorn --factory server.app:asgi_app --host 0.0.0.0 --port 8443

Deployment (see server/README.md): the client's local mitmproxy runs
`server/_relay.py`, which forwards each game-host request here with an
`X-EZ2-Host` and the account's `X-EZ2-Token`.  The lone input still taken from
the running game is its session key, recovered from the RSA login (§3.1).
"""
from __future__ import annotations

import json
import os
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import _core       # noqa: E402
import _flowshim   # noqa: E402


def _host_from(headers, fallback=''):
    h = (headers.get('x-ez2-host') or headers.get('host') or fallback or '')
    return h.split(':')[0].strip().lower()


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'ez2-pserver'

    def log_message(self, fmt, *a):   # keep our own log shape
        pass

    def _run(self):
        host = _host_from(self.headers)
        try:
            n = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            n = 0
        body = self.rfile.read(n) if n else b''
        if self.path.split('?')[0] == '/healthz':
            return self._write(200, b'ok', {'Content-Type': 'text/plain'})
        resp = _core.handle(host, self.command, self.path,
                            dict(self.headers.items()), body,
                            self.client_address[0])
        self._write(_flowshim.status_of(resp), _flowshim.body_of(resp),
                    _flowshim.headers_of(resp))

    def _write(self, status, body, headers):
        self.send_response(status)
        for k, v in (headers or {}).items():
            if k.lower() in ('content-length', 'connection', 'transfer-encoding'):
                continue
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(body or b'')))
        self.end_headers()
        if body:
            self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_DELETE = _run


# ---- ASGI callable (optional; same core) --------------------------------
async def asgi_app(scope, receive, send):
    if scope.get('type') != 'http':
        return
    headers = {k.decode('latin-1').lower(): v.decode('latin-1')
               for k, v in scope.get('headers', [])}
    host = _host_from(headers)
    raw = scope.get('raw_path') or scope.get('path', '/')
    path = raw.decode('latin-1') if isinstance(raw, (bytes, bytearray)) else str(raw)
    body = b''
    while True:
        ev = await receive()
        if ev.get('type') != 'http.request':
            break
        body += ev.get('body', b'')
        if not ev.get('more_body'):
            break
    client = scope.get('client') or ('', 0)
    if path.split('?')[0] == '/healthz':
        status, out, hdrs = 200, b'ok', {'Content-Type': 'text/plain'}
    else:
        resp = _core.handle(host, scope.get('method', 'GET'), path, headers,
                            body, client[0] if client else '')
        status, out, hdrs = _flowshim.status_of(resp), _flowshim.body_of(resp), \
            _flowshim.headers_of(resp)
    await send({'type': 'http.response.start', 'status': status,
                'headers': [(k.lower().encode(), str(v).encode())
                            for k, v in (hdrs or {}).items()]})
    await send({'type': 'http.response.body', 'body': out})


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=8081)
    ap.add_argument('--cert', help='TLS certificate (enables HTTPS)')
    ap.add_argument('--key', help='TLS private key')
    a = ap.parse_args()

    _core.load()
    httpd = ThreadingHTTPServer((a.host, a.port), Handler)
    scheme = 'http'
    if a.cert and a.key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(a.cert, a.key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = 'https'
    print(f'ez2 pserver listening on {scheme}://{a.host}:{a.port} '
          f'(threads; routes by X-EZ2-Host or Host)', flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    raise SystemExit(main())
