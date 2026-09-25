"""Mitmproxy capture addon for the private server — sweep / RE tooling only.

This is the reverse-engineering bridge that the standalone server deliberately
does **not** use.  It wraps the offline core (`server/_pserver.py`) so a sweep
run can pull chart bodies we do not hold yet from the official CDN and file them
into the archive:

  * a configured set of API endpoints (`login`, `pattern`, …) and uncached CDN
    paths are forwarded upstream verbatim, and
  * every CDN body that comes back is written to `extracted_charts/` in the same
    layout `ripper/dump_song.py` produces (see `capture_cdn_response`).

Everything else is served locally by the core.  The forwarding knobs are the
`server/data/*.txt` files written by `server/re/_exp.py`; `_sweep.py` drives this
via `_exp.py harvest`.

    mitmdump -s server/re/_capture_addon.py

This is the only remaining mitmproxy *server* addon; the standalone server
(`server/app.py` + `server/_relay.py`) never contacts an upstream.  The capture
path can be made standalone later.
"""
from __future__ import annotations

import json
import os
import sys
import traceback
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))   # server/ -> _pserver, _core, _flowshim
sys.path.insert(0, HERE)

import _core                    # noqa: E402
import _flowshim                # noqa: E402
import _pserver as ps           # noqa: E402

try:
    from mitmproxy import http  # noqa: F401  (annotations only)
except Exception:               # pragma: no cover
    http = None  # type: ignore

ROOT = ps.ROOT
DATA = ps.DATA
log = ps.log

# chart-label maps + helpers shared with the core
KM_DIR = ps.KM_DIR
DIFF_DIR = ps.DIFF_DIR
KM_LANES = ps.KM_LANES
ARCHIVE = ps.ARCHIVE
norm = ps.norm

# CDN path -> {song, keymode, levelmode, gamemode, kind}, filled from a pattern
# response and consumed when the matching CDN body comes back.
PENDING_CDN = {}
PENDING_CDN_URLS = {}


def passthrough_set():
    """Endpoints to forward to the upstream official server, from
    `passthrough_endpoints.txt` (comma-separated, e.g. `login,pattern`) or the
    legacy `passthrough_pattern` marker. Everything not listed stays stubbed,
    so scores/records remain private.

    Forwarding `login` makes the upstream mint a real session, which is what
    makes a forwarded `pattern` response valid (fresh URLs + fresh
    bundleCryptKey). Read per request, so it can be changed without a restart.
    """
    s = ps._knob('passthrough_endpoints.txt')
    eps = {p.strip() for p in s.replace(';', ',').split(',') if p.strip()}
    if os.path.exists(os.path.join(DATA, 'passthrough_pattern')):
        eps.add('pattern')
    return eps


def cdn_passthrough():
    """Forward CDN cache misses to the official CDN (harvest mode).

    Opt-in via `passthrough_endpoints.txt` containing `cdn`. Without it a miss
    is a 404 and no game-host request ever leaves the machine; this knob is the
    one explicit way to let the real CDN serve a chart we do not have yet, so it
    can be recorded and used offline from then on.
    """
    return 'cdn' in passthrough_set() or 'chart' in passthrough_set()


def _redact(v):
    if isinstance(v, str) and len(v) > 28:
        return v[:14] + f'…({len(v)})'
    return v


def summarize_obj(obj, secret=()):
    if not isinstance(obj, dict):
        return repr(obj)[:200]
    out = []
    for k, v in obj.items():
        if k in secret:
            out.append(f'{k}=<{len(v) if isinstance(v, str) else "?"}>')
        elif isinstance(v, str) and len(v) > 28:
            out.append(f'{k}={_redact(v)}')
        else:
            out.append(f'{k}={v}')
    return '{' + ', '.join(out) + '}'


def save_upstream(ep, obj):
    """Persist a decrypted upstream response: a shortened copy for reading and
    a full one (real URLs + bundleCryptKey) for reuse/diffing. Both live in the
    git-ignored server/data/."""
    try:
        red = {k: _redact(v) for k, v in obj.items()} if isinstance(obj, dict) else obj
        json.dump(red, open(os.path.join(DATA, 'last_upstream_' + ep + '.json'),
                            'w'), indent=1, ensure_ascii=False)
        json.dump(obj, open(os.path.join(DATA, 'last_upstream_' + ep + '.full.json'),
                            'w'), indent=1, ensure_ascii=False)
    except Exception:
        pass


def register_cdn_urls(req_json, resp_obj):
    """Remember which chart a pattern response's CDN paths belong to."""
    try:
        req = json.loads(req_json) if req_json else {}
    except Exception:
        req = {}
    if not isinstance(resp_obj, dict):
        return
    song = str(req.get('musicresourcename') or '')
    meta = {'song': song, 'keymode': int(req.get('keymode') or 0),
            'levelmode': int(req.get('levelmode') or 0),
            'gamemode': str(req.get('gamemode') or '')}
    for field, kind in (('final_url_ez', 'ez'), ('final_url_ezi', 'ezi')):
        u = resp_obj.get(field)
        if isinstance(u, str) and u.startswith('http'):
            _p = urllib.parse.urlsplit(u).path
            PENDING_CDN[_p] = {**meta, 'kind': kind}
            PENDING_CDN_URLS[_p] = u


def capture_cdn_response(flow):
    """File a CDN body forwarded from the official CDN into the chart archive.

    Writes `extracted_charts/<song>/<km>/<diff>/cdn_ez_*.bin` / `cdn_ezi_*.bin`
    plus an `ident.json` carrying the URLs and the label, i.e. exactly the layout
    `ripper/dump_song.py` produces and `_build_data.py` consumes — so a sweep run needs
    no separate pipeline, and the archive stays the single source of truth for
    what the server can serve. The decrypted `.ez`/`.ezi` are written too, so a
    capture can be audited with `ripper/check_charts.py` like any other dump.
    """
    p = flow.request.path.split('?')[0]
    resp = flow.response
    status = getattr(resp, 'status_code', 0)
    body = (resp.content or b'') if resp is not None else b''
    if status != 200 or not body:
        log(f'CDN FAIL {status} {p}')
        return
    meta = PENDING_CDN.get(p)
    km, lm = (meta or {}).get('keymode'), (meta or {}).get('levelmode')
    km_dir, diff_dir = KM_DIR.get(km), DIFF_DIR.get(lm)
    if not meta or not km_dir or not diff_dir:
        log(f'CDN OK {len(body)}B {p} (unfiled: no matching pattern request)')
        return
    kind = meta['kind']                      # 'ez' | 'ezi'
    d = os.path.join(ARCHIVE, norm(meta['song']) or 'song_unknown', km_dir, diff_dir)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, f'cdn_{kind}_cap.bin'), 'wb') as f:
        f.write(body)
    ident_p = os.path.join(d, 'ident.json')
    ident = {}
    if os.path.exists(ident_p):
        try:
            ident = json.load(open(ident_p))
        except Exception:
            ident = {}
    url = PENDING_CDN_URLS.get(p)
    ident['ez_url' if kind == 'ez' else 'ezi_url'] = url
    ident.setdefault('ready', True)
    ident.setdefault('bundleCryptKey', None)
    ident['capturedBy'] = 'sweep'
    lbl = ident.get('label') or {}
    lbl.update({'song': meta['song'], 'keymode': f"{KM_LANES.get(km, '?')}K",
                'lanes': KM_LANES.get(km), 'difficulty': diff_dir.upper(),
                'levelmode': str(lm), 'gamemode': meta.get('gamemode') or None,
                'labelSource': 'pattern request'})
    ident['label'] = lbl
    # Decrypt alongside, so a sweep capture is a complete dump like
    # ripper/dump_song.py's. Each file stands alone (the key pair is chosen by
    # validation), so there is no ordering requirement; failures are logged,
    # never swallowed - a silent ImportError here cost us a day.
    try:
        sys.path.insert(0, os.path.join(ROOT, 'ripper'))
        import decrypt_chart
        for kind, out_name in (('ez', 'ez.ez'), ('ezi', 'ezi.ezi')):
            src = os.path.join(d, f'cdn_{kind}_cap.bin')
            dst = os.path.join(d, out_name)
            if not os.path.exists(src) or os.path.exists(dst):
                continue
            raw = open(src, 'rb').read()
            try:
                pt, pair = decrypt_chart.decrypt_named(raw)
            except ValueError as e:
                log(f'  {kind} NOT DECRYPTED ({e}) — {os.path.relpath(d, ROOT)}')
                continue
            with open(dst, 'wb') as f:
                f.write(pt)
            ident['chartKeyPair'] = pair
            log(f'  {kind} -> {out_name} ({len(pt)}B, key pair {pair})')
        # instrumentDic.json is just the .ezi mapping (the game's own dict is
        # the same index -> basename list, only partial), so derive it
        ezi_p = os.path.join(d, 'ezi.ezi')
        dic_p = os.path.join(d, 'instrumentDic.json')
        if os.path.exists(ezi_p) and not os.path.exists(dic_p):
            rows = []
            for line in open(ezi_p, 'rb').read().decode('utf-8', 'replace').splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0].isdigit():
                    rows.append([int(parts[0]), os.path.splitext(parts[2])[0]])
            if rows:
                with open(dic_p, 'w') as f:
                    json.dump(rows, f, ensure_ascii=False)
                log(f'  instrumentDic.json ({len(rows)} entries)')
    except Exception:
        log('decrypt step failed\n' + traceback.format_exc())

    try:
        with open(ident_p, 'w') as f:
            json.dump(ident, f, indent=1, ensure_ascii=False)
    except Exception:
        log('ident.json write failed\n' + traceback.format_exc())
    log(f'CDN OK {len(body)}B {kind} -> {os.path.relpath(d, ROOT)}')


# ---------------- mitmproxy hooks ----------------

class CaptureAddon:
    def load(self, loader):
        ps.load_data()

    def request(self, flow: 'http.HTTPFlow'):
        host = (flow.request.host or '').lower()
        if host not in (ps.API_HOST, ps.RANK_HOST, ps.CDN_HOST):
            return
        try:
            path = flow.request.path.split('?')[0]
            endpoint = path.rstrip('/').split('/')[-1]
            addr = ps.flow_addr(flow)
            body = flow.request.raw_content or b''
            if host == ps.API_HOST and any(e in endpoint for e in passthrough_set()):
                # forward this endpoint upstream verbatim (the client's request
                # is already encrypted with its own session key, which the real
                # server shares — a genuine session for those endpoints only).
                # The response hook logs it before the client sees it.
                ps.bind_session(flow, endpoint, body, addr)
                log(f'{endpoint}: PASSTHROUGH to upstream (live session)')
                return
            if host == ps.CDN_HOST and cdn_passthrough() and path not in ps.CDN_PATHS:
                # harvest: no local copy, so let the official CDN answer and we
                # record the body on the way back (capture_cdn_response)
                log(f'CDN MISS {path} -> upstream (harvest)')
                return
            # everything else is answered offline by the core
            flow.response = _core.handle(
                host, flow.request.method, flow.request.path,
                dict(flow.request.headers.items()), body, addr)
        except Exception:
            # NEVER let a game-host request fall through upstream: mitmproxy
            # would proxy it to the official servers and the session becomes a
            # real/fake mix (shipped once — do not repeat).
            log('CAPTURE ADDON ERROR on', flow.request.path, '\n'
                + traceback.format_exc())
            if host == ps.CDN_HOST:
                flow.response = _flowshim.make(404, b'', {})
            else:
                flow.response = _flowshim.make(
                    502, b'private server error (see pserver.log)',
                    {'Content-Type': 'text/plain'})

    def response(self, flow: 'http.HTTPFlow'):
        """CDN bodies coming back from upstream are recorded; for a forwarded
        API endpoint the upstream response is logged (so its exact field set is
        visible), the mutate_* knobs are applied to a pattern response, and
        everything else is let through untouched."""
        host = (flow.request.host or '').lower()
        if host == ps.CDN_HOST:
            try:
                capture_cdn_response(flow)
            except Exception:
                log('CDN capture error\n' + traceback.format_exc())
            return
        if host != ps.API_HOST or flow.response is None:
            return
        ep = flow.request.path.rsplit('/', 1)[-1]
        if not any(e in ep for e in passthrough_set()):
            return
        try:
            sess = flow.metadata.get('ps_session')
            obj = ps.decrypt_api_body(flow.response.content, sess)
            if obj is None:
                log(f'{ep}: upstream response did not decrypt (stale session '
                    'key? — was the login forwarded too?)')
                return
            save_upstream(ep, obj)
            ch = None
            if ep == 'c2s_get_pattern_file' and ps.mutation_requested():
                ch = ps.mutate_pattern_response(obj, defaults=False, sess=sess)
                if ch:
                    flow.response.content = ps.encrypt_response(obj, sess)
            log(f'UPSTREAM {ep}: {summarize_obj(obj, secret=("bundleCryptKey",))}'
                + (f'  MUTATED {ch}' if ch else ''))
            if ep == 'c2s_get_pattern_file' and isinstance(obj, dict):
                register_cdn_urls(flow.metadata.get('ps_req'), obj)
                for f in ('final_url_ez', 'final_url_ezi'):
                    u = obj.get(f)
                    if isinstance(u, str):
                        q = urllib.parse.parse_qs(urllib.parse.urlsplit(u).query)
                        log(f'    {f}: path={urllib.parse.urlsplit(u).path[:70]} '
                            f'Expires={q.get("Expires")} siglen={len(q.get("Signature",[""])[0])}')
        except Exception:
            log('PASSTHROUGH response handling error\n' + traceback.format_exc())

    def error(self, flow: 'http.HTTPFlow'):
        if (flow.request.host or '').lower() in (ps.API_HOST, ps.RANK_HOST, ps.CDN_HOST):
            log(f'FLOW ERROR {flow.request.method} {flow.request.path}: '
                f'{flow.error.msg if flow.error else "?"}')


addons = [CaptureAddon()]
