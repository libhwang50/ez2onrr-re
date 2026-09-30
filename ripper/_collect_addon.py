"""Official-server collector addon — record every game-host flow + the live key.

The mitmproxy side of `ripper/collect.py`.  It is *not* a server: every request
is allowed to go to the **official** server (mitmproxy's default forwarding) and
one JSON line per flow is appended to `$EZ2_COLLECT_DIR/flows.jsonl`, carrying
the API session key that was live at the time so the encrypted bodies can be
decrypted later (`ripper/collect_read.py`).

Only the game hosts are recorded, and only what the official server answered —
nothing is served locally and the private server is not involved.

Env (set by `ripper/collect.py`; sensible defaults if run by hand):
  EZ2_COLLECT_DIR   bundle directory (default ../collected/adhoc)
  EZ2_COLLECT_HOSTS comma-separated allowlist (default the three game hosts)
  EZ2_COLLECT_CDN   '1' to also keep CDN bodies (large); default metadata only
  EZ2_COLLECT_MAX   max bytes of any recorded body, 0 = unlimited
  EZ2_SESSION_KEY   path to session_key.json (default ../server/session_key.json)
"""
from __future__ import annotations

import base64
import json
import os
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

HOSTS = {h.strip().lower() for h in os.environ.get(
    'EZ2_COLLECT_HOSTS',
    'game1-play.ez2game.co.kr,game1-rank.ez2game.co.kr,game1-cdn.ez2game.co.kr'
).split(',') if h.strip()}
CDN_HOST = 'game1-cdn.ez2game.co.kr'
OUT = os.environ.get('EZ2_COLLECT_DIR') or os.path.join(ROOT, 'collected', 'adhoc')
INCLUDE_CDN = os.environ.get('EZ2_COLLECT_CDN') == '1'
MAXBODY = int(os.environ.get('EZ2_COLLECT_MAX') or 0)
KEYFILE = os.environ.get('EZ2_SESSION_KEY') or os.path.join(ROOT, 'server', 'session_key.json')


def _b64(b):
    if not b:
        return None
    if MAXBODY and len(b) > MAXBODY:
        return None
    return base64.b64encode(b).decode('ascii')


def _key():
    try:
        d = json.load(open(KEYFILE))
        k, v = str(d.get('aes_key', '')), str(d.get('aes_iv', ''))
        if len(k) == 32 and len(v) == 16:
            return {'aes_key': k, 'aes_iv': v}
    except Exception:
        pass
    return None


class Collect:
    def __init__(self):
        self.flows = None
        self.keys = None
        self.last_key = None
        self.n = 0

    def load(self, loader):
        os.makedirs(OUT, exist_ok=True)
        self.flows = open(os.path.join(OUT, 'flows.jsonl'), 'a', buffering=1)
        self.keys = open(os.path.join(OUT, 'keys.jsonl'), 'a', buffering=1)

    def _record_key(self, key):
        if key and key != self.last_key:
            self.last_key = key
            self.keys.write(json.dumps({'t': round(time.time(), 3), **key}) + '\n')

    def _record(self, flow, status):
        req, resp = flow.request, flow.response
        host = (req.host or '').lower()
        key = _key()
        self._record_key(key)
        rlen, body = 0, None
        if resp is not None and resp.content:
            rlen = len(resp.content)
            if host != CDN_HOST or INCLUDE_CDN:
                body = _b64(resp.content)
        rec = {
            't': round(time.time(), 3),
            'host': host,
            'method': req.method,
            'path': req.path,
            'req_headers': dict(req.headers),
            'req_body_b64': _b64(req.raw_content),
            'status': status,
            'resp_len': rlen,
            'resp_headers': dict(resp.headers) if resp is not None else None,
            'resp_body_b64': body,
            'key': key,
        }
        self.flows.write(json.dumps(rec, ensure_ascii=False) + '\n')
        self.n += 1

    def response(self, flow):
        if (flow.request.host or '').lower() not in HOSTS:
            return
        try:
            self._record(flow, flow.response.status_code if flow.response else None)
        except Exception:
            pass

    def error(self, flow):
        if (flow.request.host or '').lower() not in HOSTS:
            return
        try:
            self._record(flow, None)
        except Exception:
            pass


addons = [Collect()]
