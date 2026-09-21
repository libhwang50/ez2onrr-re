"""
EZ2ON REBOOT:R — basic private server, implemented as a mitmproxy addon.

The game's Wine prefix already routes WinHTTP through mitmproxy (ProxyEnable=1,
127.0.0.1:8080) and trusts the mitmproxy CA, so this addon stubs the three
game hosts entirely server-side — no hosts-file edits, no extra certificates,
no privileged ports:

    game1-play.ez2game.co.kr   API   (AES-256-CBC/PKCS7, zf session key)
    game1-rank.ez2game.co.kr   rank  (plaintext GETs)
    game1-cdn.ez2game.co.kr    CDN   (chart/index ciphertext blobs)

Run (two terminals):

    # 1. session-key bridge (Frida -> file), leave running — it re-attaches
    #    automatically when the game restarts:
    .venv/bin/python server/_harvest_session.py

    # 2. the server itself:
    mitmdump -q -s server/_pserver.py

Then start the game as usual. The real TCP battle/control channels (raw IPs)
are untouched and keep working.

Protocol notes (all verified against captures — see AGENTS.md §3.1):
  * API request  body: form-encoded; the `data` field holds
    urlenc(b64( magic[6]=d3ad76d3adb8 || AES-CBC-PKCS7(json) )). `c2s_login`
    additionally carries `ticket` and `identity` fields.
  * API response body: b64( AES-CBC-PKCS7(json) )            (no magic)
  * key/IV = ASCII bytes of zf.aes_key (32) / zf.aes_iv (16), generated
    client-side per session (zf.gnf: RNGCryptoServiceProvider -> hex).
    The harvester writes them to server/session_key.json.

IMPORTANT: game-host requests are NEVER forwarded upstream. If handling fails,
the addon serves an explicit error instead — otherwise mitmproxy silently
proxies to the official servers and the session becomes a confusing mix of
real and fake data (this exact bug shipped once).
"""
import base64
import json
import os
import re
import time
import traceback
import urllib.parse

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from mitmproxy import http

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, 'server', 'data')
KEYFILE = os.path.join(ROOT, 'server', 'session_key.json')
LOG = open(os.path.join(ROOT, 'server', 'pserver.log'), 'a', buffering=1)

API_HOST = 'game1-play.ez2game.co.kr'
RANK_HOST = 'game1-rank.ez2game.co.kr'
CDN_HOST = 'game1-cdn.ez2game.co.kr'
MAGIC = bytes.fromhex('d3ad76d3adb8')

TEMPLATES = {}
CDN_PATHS = {}
CHARTS = []
PROFILE = {}
_profile_mtime = 0
BATTLE_SERVER = '3.37.247.33:9902'
RANK_CSV_SAMPLE = ''


def get_profile():
    """Re-read profile.json whenever its mtime changes, so edits apply live."""
    global PROFILE, _profile_mtime
    p = os.path.join(DATA, 'profile.json')
    try:
        m = os.stat(p).st_mtime
        if m != _profile_mtime:
            d = json.load(open(p))
            PROFILE = {k: v for k, v in d.items() if not k.startswith('_')}
            _profile_mtime = m
            log(f'profile.json reloaded: {PROFILE}')
    except Exception:
        pass
    return PROFILE


def log(*a):
    LOG.write(time.strftime('[%H:%M:%S] ') + ' '.join(str(x) for x in a) + '\n')


def load_data():
    for name in ('login', 'myinfo', 'gameinfo'):
        p = os.path.join(DATA, name + '.json')
        if os.path.exists(p):
            TEMPLATES[name] = json.load(open(p))
    global CDN_PATHS, CHARTS, RANK_CSV_SAMPLE
    p = os.path.join(DATA, 'cdn_paths.json')
    if os.path.exists(p):
        CDN_PATHS = json.load(open(p))
    p = os.path.join(DATA, 'charts.json')
    if os.path.exists(p):
        CHARTS = json.load(open(p))
    p = os.path.join(DATA, 'rank_sample.csv')
    if os.path.exists(p):
        RANK_CSV_SAMPLE = open(p).read().strip()
    get_profile()
    log(f'data loaded: templates={sorted(TEMPLATES)} cdn={len(CDN_PATHS)} charts={len(CHARTS)}')


# ---------------- crypto ----------------

def pkcs7_pad(b):
    n = 16 - len(b) % 16
    return b + bytes([n]) * n


def pkcs7_unpad(b):
    if not b or len(b) % 16:
        raise ValueError('bad block length')
    n = b[-1]
    if not 1 <= n <= 16 or b[-n:] != bytes([n]) * n:
        raise ValueError('bad padding')
    return b[:-n]


def session_key():
    """Return (key_bytes, iv_bytes, age_seconds) or None."""
    try:
        st = os.stat(KEYFILE)
        d = json.load(open(KEYFILE))
        k, v = str(d.get('aes_key', '')), str(d.get('aes_iv', ''))
        if len(k) == 32 and len(v) == 16:
            return k.encode(), v.encode(), time.time() - st.st_mtime
    except Exception:
        pass
    return None


def parse_form(body: bytes):
    """The API posts form fields (data=..., and ticket=/identity= on login).
    Returns the url-decoded `data` value, or None."""
    text = body.decode('utf-8', 'replace')
    for part in text.split('&'):
        k, _, v = part.partition('=')
        if k == 'data':
            return urllib.parse.unquote(v)
    return None


def decrypt_request(body: bytes):
    """API request -> (json_text, error). Never raises."""
    enc = parse_form(body)
    if enc is None:
        return None, 'no data= field'
    try:
        raw = base64.b64decode(enc + '=' * (-len(enc) % 4))
    except Exception as e:
        return None, f'bad base64: {e}'
    if raw[:6] != MAGIC:
        return None, f'bad magic {raw[:6].hex()}'
    sk = session_key()
    if sk is None:
        return None, 'no session key'
    key, iv, _age = sk
    try:
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        pt = pkcs7_unpad(dec.update(raw[6:]) + dec.finalize())
        return pt.decode('utf-8', 'replace'), None
    except Exception as e:
        return None, f'decrypt failed (stale session key?): {e}'


def encrypt_response(json_obj) -> bytes:
    sk = session_key()
    if sk is None:
        raise RuntimeError('no session key')
    key, iv, _age = sk
    pt = json.dumps(json_obj, separators=(',', ':'), ensure_ascii=False).encode()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(pkcs7_pad(pt)) + enc.finalize()
    return base64.b64encode(ct)


# ---------------- endpoint handlers ----------------

def apply_profile(d):
    """Merge profile overrides into a member/memberinfo dict (recursive)."""
    prof = get_profile()

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in prof:
                    o[k] = prof[k]
                else:
                    walk(v)
        elif isinstance(o, list):
            for x in o:
                walk(x)
    walk(d)
    return d


def handle_api(flow: http.HTTPFlow):
    path = flow.request.path.split('?')[0]
    endpoint = path.rstrip('/').split('/')[-1]
    req_json, err = decrypt_request(flow.request.raw_content or b'')
    if err:
        log(f'WARN {endpoint}: request not decrypted ({err})')
    else:
        log(f'{endpoint} request: {req_json[:300]}')

    if endpoint == 'c2s_login':
        # wait briefly for the harvester — the client generates the key just
        # before this request lands, and the harvester may still be re-
        # attaching after a game restart. The client's own timeout is the limit.
        waited = False
        for _ in range(60):          # up to 15 s
            if session_key():
                break
            waited = True
            time.sleep(0.25)
        sk = session_key()
        if sk is None:
            log('ERROR: no session key for login — is _harvest_session.py '
                'running and attached to this game session?')
            flow.response = http.Response.make(
                502, b'private server: no session key',
                {'Content-Type': 'text/plain'})
            return
        if waited:
            log('login: key arrived while waiting')
        log(f"login: serving template under key {sk[0][:8].decode()}... "
            f"(key file {sk[2]:.0f}s old)")
        tpl = TEMPLATES.get('login')
        if tpl is None:
            return respond_api(flow, {'result': 0})
        return respond_api(flow, apply_profile(tpl))

    if endpoint == 'c2s_get_gameinfo':
        tpl = TEMPLATES.get('gameinfo')
        if tpl is None:
            return respond_api(flow, {'result': 0})
        return respond_api(flow, tpl)

    if endpoint == 'c2s_get_myinfo':
        tpl = TEMPLATES.get('myinfo')
        if tpl is None:
            return respond_api(flow, {'result': 0})
        return respond_api(flow, apply_profile(tpl))

    if endpoint == 'c2s_get_userinfo':
        return respond_api(flow, userinfo_response(req_json))

    if endpoint == 'c2s_get_pattern_file':
        return respond_api(flow, pattern_response(req_json))

    if endpoint == 'c2s_set_game_clear':
        # refinement candidate: the real response is 48 B of ciphertext; the
        # client accepted {"result":1}-shaped guesses so far (unvalidated — the
        # validated response in the first test actually came from upstream).
        cfg = os.path.join(DATA, 'set_game_clear.json')
        tpl = json.load(open(cfg)) if os.path.exists(cfg) else {'result': 1}
        return respond_api(flow, tpl)

    log(f'UNKNOWN api endpoint {path} — returning generic result')
    return respond_api(flow, {'result': 1})


def norm(s):
    return re.sub(r'[^a-z0-9]', '', (s or '').lower())


def pattern_response(req_json):
    """c2s_get_pattern_file: (musicresourcename, keymode, levelmode) -> URLs.

    Exact matches only — serving a different keymode/difficulty chart for the
    selected one would load wrong notes."""
    try:
        req = json.loads(req_json) if req_json else {}
    except Exception:
        req = {}
    name = str(req.get('musicresourcename') or req.get('MUSIC_RESOURCE_NAME') or '')
    km = int(req.get('keymode') or req.get('KEYMODE') or 0)
    lm = int(req.get('levelmode') or req.get('LEVELMODE') or 0)
    want = norm(name)
    hit = next((c for c in CHARTS if c['song_norm'] == want and c['keymode'] == km
                and c['levelmode'] == lm), None)
    if hit is None:
        have = sorted({c['song_norm'] for c in CHARTS})
        log(f'pattern: NO exact chart for {name!r} keymode={km} levelmode={lm} '
            f'(known songs: {have})')
        return {'result': 0}
    base = f'https://{CDN_HOST}'
    resp = {
        'final_url_ez': f"{base}{hit['ez_path']}?Expires=4102444800&Signature=private&Key-Pair-Id=K2L5B5JS5W46ST",
        'final_url_ezi': f"{base}{hit['ezi_path']}?Expires=4102444800&Signature=private&Key-Pair-Id=K2L5B5JS5W46ST",
        'bundleCryptKey': bundle_crypt_key(),
        'result': 1,
    }
    log(f"pattern: {name!r} km={km} lm={lm} -> {hit['keymode_dir']}/{hit['levelmode_dir']}")
    return resp


def bundle_crypt_key():
    p = os.path.join(DATA, 'bundleCryptKey.txt')
    if os.path.exists(p):
        return open(p).read().strip()
    return '0' * 96


def userinfo_response(req_json):
    """c2s_get_userinfo: {"appid":...,"steamId":[UInt64,...]} — the leaderboard
    profile fetch (up to ~10 players at once).

    The real response shape is not yet captured; the client crashed on a
    single-memberinfo body, so serve a LIST with one entry per requested
    steamId. Tune data/userinfo_entry.json once a real capture lands."""
    try:
        req = json.loads(req_json) if req_json else {}
    except Exception:
        req = {}
    ids = req.get('steamId') or req.get('SteamId') or []
    if not isinstance(ids, list):
        ids = [ids]
    tpl_p = os.path.join(DATA, 'userinfo_entry.json')
    tpl = json.load(open(tpl_p)) if os.path.exists(tpl_p) else {
        'MEMBER_ID': 0, 'STATUS': 0, 'PLATE': 1,
        'ACC_DATE': '2026-01-01T00:00:00', 'REG_DATE': '2026-01-01T00:00:00',
        'ROUND': 0, 'LEVEL': 98, 'EXP': 0, 'NEXT_EXP': 0, 'RATING': 4.978,
        'NICKNAME': 'player', 'STEAM_ID': '0',
    }
    entries = []
    for sid in ids:
        e = dict(tpl)
        e['STEAM_ID'] = str(sid)
        e['NICKNAME'] = f'player_{str(sid)[-4:]}'
        entries.append(e)
    log(f'get_userinfo: {len(entries)} profile(s) served (shape = GUESS, see README)')
    return {'memberinfo': entries, 'result': 1}


def respond_api(flow, obj):
    flow.response = http.Response.make(
        200, encrypt_response(obj),
        {'Content-Type': 'application/json'})


def handle_rank(flow: http.HTTPFlow):
    q = flow.request.query.get('data', '')
    arg = q.split(',')[0]
    if arg == 'get_battle_server_ip':
        body = BATTLE_SERVER.encode()
    elif q.startswith('get') and q != 'get_battle_server_ip' and arg[3:].isdigit():
        # a leaderboard query — serve the real captured CSV when we have it
        # (Top100 / MyRange for a captured song), else the static sample
        csv = os.path.join(DATA, 'rank_csv', q.replace(',', '_') + '.csv')
        body = open(csv).read().encode() if os.path.exists(csv) else RANK_CSV_SAMPLE.encode()
    elif q.startswith('plf'):
        log(f'score upload: {urllib.parse.unquote(q)[:200]}')
        body = b''
    else:
        # rating / totalranking / getcoursedata / misc — empty matches the
        # official servers' own responses
        if not q.startswith(('rating', 'totalranking')):
            log(f'rank query served empty: {q[:120]}')
        body = b''
    flow.response = http.Response.make(
        200, body, {'Content-Type': 'application/json'})


def handle_cdn(flow: http.HTTPFlow):
    p = flow.request.path.split('?')[0]
    rel = CDN_PATHS.get(p)
    if rel is None:
        log(f'CDN MISS {p}')
        flow.response = http.Response.make(404, b'', {'Content-Type': 'text/plain'})
        return
    data = open(os.path.join(ROOT, rel), 'rb').read()
    flow.response = http.Response.make(
        200, data, {'Content-Type': 'application/octet-stream'})


# ---------------- mitmproxy hooks ----------------

class PrivateServer:
    def load(self, loader):
        load_data()

    def request(self, flow: http.HTTPFlow):
        host = (flow.request.host or '').lower()
        if host not in (API_HOST, RANK_HOST, CDN_HOST):
            return
        try:
            if host == API_HOST:
                log(f'>>> {flow.request.method} {flow.request.path}')
                handle_api(flow)
            elif host == RANK_HOST:
                handle_rank(flow)
            else:
                handle_cdn(flow)
        except Exception:
            # NEVER let a game-host request fall through upstream: mitmproxy
            # would proxy it to the official servers and the session becomes a
            # real/fake mix (shipped once — do not repeat).
            log('ADDON ERROR on', flow.request.path, '\n' + traceback.format_exc())
            if host == CDN_HOST:
                flow.response = http.Response.make(404, b'', {})
            else:
                flow.response = http.Response.make(
                    502, b'private server error (see pserver.log)',
                    {'Content-Type': 'text/plain'})

    def error(self, flow: http.HTTPFlow):
        if (flow.request.host or '').lower() in (API_HOST, RANK_HOST, CDN_HOST):
            log(f'FLOW ERROR {flow.request.method} {flow.request.path}: '
                f'{flow.error.msg if flow.error else "?"}')


addons = [PrivateServer()]
