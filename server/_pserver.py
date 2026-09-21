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

    # 1. session-key bridge (Frida -> file), leave running:
    .venv/bin/python server/_harvest_session.py

    # 2. the server itself:
    mitmdump -q -s server/_pserver.py

Then start the game as usual. The real TCP battle/control channels (raw IPs)
are untouched and keep working.

Protocol notes (all verified against captures — see AGENTS.md §3.1):
  * API request  body: data=<urlenc b64( magic[6]=d3ad76d3adb8 || AES-CBC-PKCS7(json) )>
  * API response body: b64( AES-CBC-PKCS7(json) )            (no magic)
  * key/IV = ASCII bytes of zf.aes_key (32) / zf.aes_iv (16), generated
    client-side per session (zf.gnf: RNGCryptoServiceProvider -> hex).
    The harvester writes them to server/session_key.json.
"""
import base64
import json
import os
import re
import time
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
BATTLE_SERVER = '3.37.247.33:9902'
RANK_CSV_SAMPLE = ''


def log(*a):
    LOG.write(time.strftime('[%H:%M:%S] ') + ' '.join(str(x) for x in a) + '\n')


def load_data():
    for name in ('login', 'myinfo', 'gameinfo'):
        p = os.path.join(DATA, name + '.json')
        if os.path.exists(p):
            TEMPLATES[name] = json.load(open(p))
    p = os.path.join(DATA, 'cdn_paths.json')
    if os.path.exists(p):
        global CDN_PATHS
        CDN_PATHS = json.load(open(p))
    p = os.path.join(DATA, 'charts.json')
    if os.path.exists(p):
        global CHARTS
        CHARTS = json.load(open(p))
    p = os.path.join(DATA, 'profile.json')
    prof = json.load(open(p)) if os.path.exists(p) else {}
    global PROFILE
    PROFILE = {k: v for k, v in prof.items() if not k.startswith('_')}
    p = os.path.join(DATA, 'rank_sample.csv')
    global RANK_CSV_SAMPLE
    if os.path.exists(p):
        RANK_CSV_SAMPLE = open(p).read().strip()
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


def aes_cbc(key, iv, data):
    c = Cipher(algorithms.AES(key), modes.CBC(iv))
    return c


def session_key():
    """Return (key_bytes, iv_bytes) or None."""
    try:
        d = json.load(open(KEYFILE))
        k, v = d.get('aes_key', ''), d.get('aes_iv', '')
        if isinstance(k, str) and len(k) == 32 and len(v) == 16:
            return k.encode(), v.encode()
    except Exception:
        pass
    return None


def decrypt_request(body: bytes):
    """data=<urlenc b64(magic||ct)> -> (json_text, error)."""
    text = body.decode('utf-8', 'replace')
    if not text.startswith('data='):
        return None, 'no data= prefix'
    enc = urllib.parse.unquote(text[5:])
    raw = base64.b64decode(enc + '=' * (-len(enc) % 4))
    if raw[:6] != MAGIC:
        return None, f'bad magic {raw[:6].hex()}'
    ct = raw[6:]
    sk = session_key()
    if sk is None:
        return None, 'no session key yet'
    key, iv = sk
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    pt = pkcs7_unpad(dec.update(ct) + dec.finalize())
    return pt.decode('utf-8', 'replace'), None


def encrypt_response(json_obj) -> bytes:
    sk = session_key()
    if sk is None:
        raise RuntimeError('no session key')
    key, iv = sk
    pt = json.dumps(json_obj, separators=(',', ':'), ensure_ascii=False).encode()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(pkcs7_pad(pt)) + enc.finalize()
    return base64.b64encode(ct)


# ---------------- endpoint handlers ----------------

def apply_profile(d):
    """Merge profile overrides into a member/memberinfo dict (recursive)."""
    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in PROFILE:
                    o[k] = PROFILE[k]
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
        # before this request lands
        for _ in range(20):
            if session_key():
                break
            time.sleep(0.25)
        tpl = TEMPLATES.get('login')
        if tpl is None:
            return respond_api(flow, {'result': 0})
        return respond_api(flow, apply_profile(tpl))

    if endpoint == 'c2s_get_gameinfo':
        tpl = TEMPLATES.get('gameinfo')
        if tpl is None:
            return respond_api(flow, {'result': 0})
        return respond_api(flow, tpl)

    if endpoint in ('c2s_get_myinfo', 'c2s_get_userinfo'):
        tpl = TEMPLATES.get('myinfo')
        if tpl is None:
            return respond_api(flow, {'result': 0})
        return respond_api(flow, apply_profile(tpl))

    if endpoint == 'c2s_get_pattern_file':
        return respond_api(flow, pattern_response(req_json))

    if endpoint == 'c2s_set_game_clear':
        # refinement candidate: real response is 48 B ciphertext; {"result":1}
        # is the minimal guess until a keyed capture reveals the fields.
        cfg = os.path.join(DATA, 'set_game_clear.json')
        tpl = json.load(open(cfg)) if os.path.exists(cfg) else {'result': 1}
        return respond_api(flow, tpl)

    log(f'UNKNOWN api endpoint {path} — returning generic result')
    return respond_api(flow, {'result': 1})


def norm(s):
    return re.sub(r'[^a-z0-9]', '', (s or '').lower())


def pattern_response(req_json):
    """c2s_get_pattern_file: (musicresourcename, keymode, levelmode) -> URLs."""
    if req_json:
        try:
            req = json.loads(req_json)
        except Exception:
            req = {}
    else:
        req = {}
    name = str(req.get('musicresourcename') or req.get('MUSIC_RESOURCE_NAME') or '')
    km = int(req.get('keymode') or req.get('KEYMODE') or 0)
    lm = int(req.get('levelmode') or req.get('LEVELMODE') or 0)
    want = norm(name)
    hit = next((c for c in CHARTS if c['song_norm'] == want and c['keymode'] == km
                and c['levelmode'] == lm), None)
    if hit is None:  # fall back to any difficulty of that song+keymode
        hit = next((c for c in CHARTS if c['song_norm'] == want and c['keymode'] == km), None)
    if hit is None:  # fall back to song only
        hit = next((c for c in CHARTS if c['song_norm'] == want), None)
    if hit is None:
        log(f'pattern: NO CHART for {name!r} keymode={km} levelmode={lm}')
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
        body = RANK_CSV_SAMPLE.encode()
    elif q.startswith('plf'):
        log(f'score upload: {urllib.parse.unquote(q)[:200]}')
        body = b''
    else:
        # rating / totalranking / misc — captured as Content-Length: 0
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
        if host == API_HOST:
            if not flow.request.path.startswith('/api/'):
                return
            log(f'>>> {flow.request.method} {flow.request.path}')
            handle_api(flow)
        elif host == RANK_HOST:
            handle_rank(flow)
        elif host == CDN_HOST:
            handle_cdn(flow)


addons = [PrivateServer()]
