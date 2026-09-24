"""Client-side relay addon: forward the game's hosts to a remote standalone server.

Runs under the **client's** mitmproxy (which already MITMs the game's TLS and is
trusted by the Wine prefix).  For each of the game's three hosts it forwards the
request to the remote server (`server/app.py`) with an `X-EZ2-Host` header (the
remote routes by it) and the account's `X-EZ2-Token`.  No game logic here — this
is the thin edge that makes the standalone server deployable.

    EZ2_REMOTE=https://ez2.example.com mitmdump -s server/_relay.py

Config via environment or `server/data/relay.json`:
    remote      base URL of the standalone server   (default http://127.0.0.1:8081)
    token_file  file holding the account token      (else $EZ2_TOKEN)
    insecure    true = accept a self-signed remote cert
"""
from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request

from mitmproxy import http

HERE = os.path.dirname(os.path.abspath(__file__))
API_HOST = 'game1-play.ez2game.co.kr'
RANK_HOST = 'game1-rank.ez2game.co.kr'
CDN_HOST = 'game1-cdn.ez2game.co.kr'
GAME_HOSTS = (API_HOST, RANK_HOST, CDN_HOST)


def _truthy(v):
    return str(v).strip().lower() not in ('', '0', 'false', 'no', 'off')


def _config():
    cfg = {}
    try:
        with open(os.path.join(HERE, 'data', 'relay.json')) as f:
            cfg = json.load(f)
    except Exception:
        pass
    remote = (os.environ.get('EZ2_REMOTE') or cfg.get('remote')
              or 'http://127.0.0.1:8081').rstrip('/')
    token_file = os.environ.get('EZ2_TOKEN_FILE') or cfg.get('token_file') or ''
    insecure = _truthy(os.environ.get('EZ2_INSECURE', cfg.get('insecure', False)))
    return remote, token_file, insecure


def _token(token_file):
    tok = os.environ.get('EZ2_TOKEN') or ''
    if not tok and token_file:
        try:
            tok = open(token_file).read().strip()
        except Exception:
            tok = ''
    return tok


class Relay:
    def request(self, flow: http.HTTPFlow):
        host = (flow.request.host or '').lower()
        if host not in GAME_HOSTS:
            return
        remote, token_file, insecure = _config()
        headers = {'X-EZ2-Host': host}
        tok = _token(token_file)
        if tok:
            headers['X-EZ2-Token'] = tok
        ct = flow.request.headers.get('content-type')
        if ct:
            headers['Content-Type'] = ct
        body = flow.request.raw_content or b''
        req = urllib.request.Request(
            remote + flow.request.path,
            data=(body if flow.request.method != 'GET' else None),
            method=flow.request.method, headers=headers)
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
                status, out = r.status, r.read()
                ctype = r.headers.get('Content-Type', 'application/octet-stream')
        except urllib.error.HTTPError as e:
            status, out = e.code, e.read()
            ctype = e.headers.get('Content-Type', 'application/octet-stream')
        except Exception as e:
            flow.response = http.Response.make(
                502, f'relay error: {e}'.encode(),
                {'Content-Type': 'text/plain'})
            return
        flow.response = http.Response.make(status, out, {'Content-Type': ctype})


addons = [Relay()]
