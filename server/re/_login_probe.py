#!/usr/bin/env python3
"""Decisive experiment: does `c2s_login.data` carry the session key/IV?

Working hypothesis (§3.1): the login `data` field is one 2048-bit
RSA block, encrypted under the build's baked-in `zf.publicKey`, whose plaintext
is `key(32 ASCII hex) || iv(16 ASCII hex)` — i.e. the client's live API session
key.  The private server owns a keypair and the drop-in `version.dll` rewrites
`zf.publicKey` to ours, so the server can recover the key with no Frida.

This addon does **only** that one measurement, so it is independent of the full
private server and of the memory harvester:

    mitmdump -s server/re/_login_probe.py

Install the patcher DLL first (`client/patcher/install.sh patcher`) and launch
the game; its automatic login fires the request.  Every login is saved to
`server/data/login_probe_<n>.{bin,json,plain.bin}` and classified in
`server/login_probe.log`.

Why a dedicated probe: the previous `_rsa.decrypt` used `cryptography`'s
PKCS#1 v1.5 decrypt as a validity oracle, which (as of at least v48) strips at
the first 0x00 without checking the `00 02` prefix and therefore "succeeds" on
~82% of *random* blocks.  Every earlier "login RSA decrypted" log line was
noise.  `_rsa.decrypt` now does a strict raw-RSA decode; this probe is how we
confirm the swap is actually active before building anything on top of it.
"""
import base64
import json
import os
import re
import sys
import time
import urllib.parse

from mitmproxy import http

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # the server/ dir
sys.path.insert(0, HERE)
import _rsa  # noqa: E402

ROOT = os.path.dirname(HERE)
DATA = os.path.join(HERE, 'data')
LOGIN_HOST = 'game1-play.ez2game.co.kr'
LOG = open(os.path.join(HERE, 'login_probe.log'), 'a', buffering=1)
_count = [0]

_HEX32 = re.compile(rb'^[0-9A-Fa-f]{32}$')
_HEX16 = re.compile(rb'^[0-9A-Fa-f]{16}$')


def log(*a):
    LOG.write(time.strftime('[%H:%M:%S] ') + ' '.join(str(x) for x in a) + '\n')


def parse_form(body: bytes):
    """field -> first value, url-decoded (data/ticket/identity on login)."""
    out = {}
    for part in body.decode('utf-8', 'replace').split('&'):
        k, _, v = part.partition('=')
        if k and k not in out:
            out[k] = urllib.parse.unquote(v)
    return out


def classify(pt: bytes) -> str:
    try:
        d = json.loads(pt.decode('utf-8'))
        if isinstance(d, dict) and d.get('key') and d.get('iv'):
            if len(str(d['key'])) == 32 and len(str(d['iv'])) == 16:
                return 'KEY_IV_JSON'
    except Exception:
        pass
    if len(pt) == 48 and _HEX32.match(pt[:32]) and _HEX16.match(pt[32:]):
        return 'KEY_IV_HEX'
    if len(pt) == 48:
        return 'len48-not-hex'
    printable = sum(32 <= c < 127 for c in pt)
    return f'len{len(pt)} printable={printable}'


class LoginProbe:
    def request(self, flow: http.HTTPFlow):
        host = (flow.request.host or '').lower()
        if host != LOGIN_HOST:
            return
        if flow.request.path.rstrip('/').rsplit('/', 1)[-1] != 'c2s_login':
            return
        _count[0] += 1
        i = _count[0]
        form = parse_form(flow.request.raw_content or b'')
        log(f'login #{i} path={flow.request.path} fields={sorted(form)}')
        for k in ('ticket', 'identity'):
            if k in form:
                log(f'  {k}={form[k][:80]}')
        enc = form.get('data', '')
        try:
            raw = base64.b64decode(enc + '=' * (-len(enc) % 4))
        except Exception as e:
            log(f'  data is not base64 ({e})')
            return
        open(os.path.join(DATA, f'login_probe_{i}.bin'), 'wb').write(raw)
        with open(os.path.join(DATA, f'login_probe_{i}.json'), 'w') as f:
            json.dump({'path': flow.request.path, 'fields': form}, f, indent=1)
        log(f'  data={len(raw)}B head={raw[:8].hex()}')

        if len(raw) not in (128, 256, 384, 512):
            log('  not a single RSA block (swap irrelevant or shape changed)')
            return
        label, pt = _rsa.decrypt(raw)
        if pt is None:
            log('  strict RSA: REJECTED — block is not encrypted under our '
                'public key (is the patcher version.dll installed?)')
            return
        open(os.path.join(DATA, f'login_probe_{i}.plain.bin'), 'wb').write(pt)
        verdict = classify(pt)
        log(f'  strict RSA ({label}): {len(pt)}B {pt[:64].hex()}')
        log(f'  => {verdict}')
        if verdict in ('KEY_IV_JSON', 'KEY_IV_HEX'):
            if verdict == 'KEY_IV_JSON':
                d = json.loads(pt.decode('utf-8'))
                log(f'  *** CONFIRMED: login JSON steamid={d.get("steamid")} '
                    f'key={d.get("key")} iv={d.get("iv")}')
            else:
                log(f'  *** HYPOTHESIS CONFIRMED: key={pt[:32].decode()} '
                    f'iv={pt[32:].decode()}')
        else:
            log('  *** payload is neither the login key/iv JSON nor a bare '
                'key||iv blob — the client build changed shape (see the saved '
                '.plain.bin)')


addons = [LoginProbe()]
