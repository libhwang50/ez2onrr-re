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
import hashlib
import json
import os
import re
import sys
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
# paths the last pattern responses pointed at: {path: {song,keymode,levelmode,
# gamemode,kind}} - so a forwarded CDN body can be filed under the chart it is
PENDING_CDN = {}
PENDING_CDN_URLS = {}
ARCHIVE = os.path.join(ROOT, 'extracted_charts')
KM_DIR = {1: '4k', 2: '5k', 3: '6k', 4: '8k', 5: '7k'}
DIFF_DIR = {1: 'ez', 2: 'nm', 3: 'hd', 4: 'shd'}
KM_LANES = {1: 4, 2: 5, 3: 6, 4: 8, 5: 7}
CHARTS = []
PATTERN_REPLAY = {}
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


PASSTHROUGH_PATTERN = False

def load_data():
    global BATTLE_SERVER
    p = os.path.join(DATA, 'battle_server.txt')
    if os.path.exists(p):
        BATTLE_SERVER = open(p).read().strip() or BATTLE_SERVER
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
    p = os.path.join(DATA, 'pattern_replay.json')
    if os.path.exists(p):
        global PATTERN_REPLAY
        PATTERN_REPLAY = json.load(open(p))
    p = os.path.join(DATA, 'rank_sample.csv')
    if os.path.exists(p):
        RANK_CSV_SAMPLE = open(p).read().strip()
    get_profile()
    global PASSTHROUGH_PATTERN
    PASSTHROUGH_PATTERN = os.path.exists(os.path.join(DATA, 'passthrough_pattern'))
    log(f'data loaded: templates={sorted(TEMPLATES)} cdn={len(CDN_PATHS)} charts={len(CHARTS)} '
        f'passthrough_pattern={PASSTHROUGH_PATTERN} endpoints={sorted(passthrough_set()) or "-"} '
        f'knobs={[n for n in ("mutate_urls.txt", "mutate_bck.txt") if _knob(n)] or "-"}')


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


BCK_PAYLOAD_FILE = os.path.join(DATA, 'bck_payload.hex')


def bck_payload():
    """The 32-byte plaintext the client expects inside bundleCryptKey.

    bundleCryptKey is AES-256-CBC/PKCS7(32-byte payload) under the client's live
    session key/IV — the same cipher as the API bodies. The payload is a
    **build-time constant of the client**, not session material: two captured
    tokens from different key material decrypted to the same 32 bytes. So the
    server does not need an official response at all — it encrypts this constant.

    Order: server/data/bck_payload.hex (git-ignored), else derive it from the
    last captured upstream pattern response (works when the capture is from the
    same session key), else zeros with a warning.
    """
    try:
        h = open(BCK_PAYLOAD_FILE).read().strip()
        if len(h) == 64:
            return bytes.fromhex(h)
    except Exception:
        pass
    sk = session_key()
    p = os.path.join(DATA, 'last_upstream_c2s_get_pattern_file.full.json')
    if sk:
        key, iv, _age = sk
        try:
            b = json.load(open(p))['bundleCryptKey']
            raw = base64.b64decode(b + '=' * (-len(b) % 4))
            dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            pl = pkcs7_unpad(dec.update(raw) + dec.finalize())
            if len(pl) == 32:
                log(f'  bck payload derived from the last capture ({pl.hex()[:16]}…)')
                return pl
        except Exception:
            pass
    log('  WARNING: no bck payload constant available — falling back to zeros')
    return bytes(32)


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


def session_encrypt(raw: bytes) -> bytes:
    """AES-256-CBC/PKCS7 under the client's own session key (raw ciphertext).

    Same primitive the API bodies use; `bundleCryptKey` is this over a 32-byte
    payload (see the `mint` bck mode)."""
    sk = session_key()
    if sk is None:
        raise RuntimeError('no session key')
    key, iv, _age = sk
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(pkcs7_pad(raw)) + enc.finalize()


def encrypt_response(json_obj) -> bytes:
    pt = json.dumps(json_obj, separators=(',', ':'), ensure_ascii=False).encode()
    return base64.b64encode(session_encrypt(pt))


def decrypt_api_body(body: bytes):
    """An upstream API response body -> json object, or None. Never raises.

    Same cipher as encrypt_response (b64 of AES-CBC/PKCS7 under the client's
    own session key — upstream encrypts with the key the client uses)."""
    sk = session_key()
    if sk is None:
        return None
    key, iv, _age = sk
    b = (body or b'').strip()
    try:
        raw = base64.b64decode(b + b'=' * (-len(b) % 4))
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return json.loads(pkcs7_unpad(dec.update(raw) + dec.finalize()).decode('utf-8'))
    except Exception:
        return None


# ---------------- response mutation (the 8CN26 isolation experiments) ----
#
# Knobs are read per response, so an experiment needs no restart of mitmdump:
#
#   server/data/mutate_urls.txt   future | expire | noparams | host
#   server/data/mutate_bck.txt    stale | garbage | empty | mint[:payload] | literal:<b64>
#   server/data/chart_mode.txt    exact (default) | any   (serve the song's chart
#                                 for an uncaptured keymode/difficulty too)
#
#   future    Expires far in the future (signature no longer matches)
#   expire    Expires in the past (signature still valid)
#   noparams  strip the whole query string
#   host      swap the CDN host (same path/params)
#   stale     the older captured bundleCryptKey (real, wrong session)
#   garbage   48 random bytes, valid base64 shape
#   mint      a token we build ourselves: AES-256-CBC/PKCS7 of a 32-byte payload
#             under the live session key. Plain `mint` uses the client's own
#             constant payload, so it yields a byte-perfect token with no official
#             server involved. mint:zero, mint:random, mint:<64 hex>, mint:<text>
#
# Removing both files restores the untouched response.

def _knob(name):
    try:
        return open(os.path.join(DATA, name)).read().strip()
    except Exception:
        return ''


def mutation_requested():
    return bool(_knob('mutate_urls.txt') or _knob('mutate_bck.txt'))


def passthrough_set():
    """Endpoints to forward to the upstream official server, from
    `passthrough_endpoints.txt` (comma-separated, e.g. `login,pattern`) or the
    legacy `passthrough_pattern` marker. Everything not listed stays stubbed,
    so scores/records remain private.

    Forwarding `login` makes the upstream mint a real session, which is what
    makes a forwarded `pattern` response valid (fresh URLs + fresh
    bundleCryptKey). Read per request, so it can be changed without a restart.
    """
    s = _knob('passthrough_endpoints.txt')
    eps = {p.strip() for p in s.replace(';', ',').split(',') if p.strip()}
    if os.path.exists(os.path.join(DATA, 'passthrough_pattern')):
        eps.add('pattern')
    return eps


def upstream_like_headers():
    """The headers the real nginx API returns; the client has only ever seen
    these, so mimic them (mp-14: our own responses had almost none)."""
    return {
        'Content-Type': 'application/json',
        'Server': 'nginx',
        'Connection': 'keep-alive',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-Content-Type-Options': 'nosniff',
        'X-XSS-Protection': '1; mode=block',
    }


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


def mutate_url(u, mode):
    if mode == 'noparams':
        return u.split('?')[0]
    try:
        parts = urllib.parse.urlsplit(u)
        q = dict(urllib.parse.parse_qsl(parts.query))
    except Exception:
        return u
    if mode == 'future':
        q['Expires'] = str(int(time.time()) + 315360000)   # +10 years
    elif mode == 'expire':
        q['Expires'] = str(int(time.time()) - 3600)
    elif mode == 'now':
        # mint a fresh-looking expiry exactly like the official server does
        # (Expires ~150 s out). The signature stays whatever it was — proven
        # irrelevant by the `urls skew` test — so this is a fully offline URL.
        q['Expires'] = str(int(time.time()) + 150)
    elif mode == 'skew':
        # +1 s: still perfectly "fresh" for any expiry-window check, but the
        # CloudFront signature no longer matches -> isolates signature
        # verification from a freshness/expiry check.
        try:
            q['Expires'] = str(int(q.get('Expires', '0')) + 1)
        except Exception:
            pass
    if mode == 'host':
        parts = parts._replace(netloc='game1-cdn2.ez2game.co.kr')
    return urllib.parse.urlunsplit(parts._replace(
        query=urllib.parse.urlencode(q)))


def mutate_pattern_response(obj):
    """Apply the knob files. Returns a list of applied changes, or None."""
    m_url, m_bck = _knob('mutate_urls.txt'), _knob('mutate_bck.txt')
    if not (m_url or m_bck) or not isinstance(obj, dict):
        return None
    changed = []
    if m_url:
        if cdn_passthrough():
            # The URLs are about to be fetched from the real CloudFront, which
            # verifies the signature. Rewriting Expires (or the params/host)
            # invalidates it -> 403 for every chart. Skip and say so loudly.
            log(f'  WARNING: ignoring urls={m_url} — cdn passthrough is on and '
                f'CloudFront checks the upstream signature (use `_exp.py offline` '
                f'for minted URLs)')
            m_url = ''
        for f in ('final_url_ez', 'final_url_ezi'):
            if m_url and isinstance(obj.get(f), str):
                obj[f] = mutate_url(obj[f], m_url)
                changed.append(f'{f}={m_url}')
    if m_bck:
        if m_bck == 'harvested':
            # the bCK from the last official pattern response in THIS session:
            # the client appears to check that the response echoes its own
            # session token, so reusing the captured value should pass.
            p = os.path.join(DATA, 'last_upstream_c2s_get_pattern_file.full.json')
            try:
                obj['bundleCryptKey'] = json.load(open(p))['bundleCryptKey']
                log(f'  bck=harvested ({obj["bundleCryptKey"][:12]}…)')
            except Exception as e:
                log(f'  bck=harvested: could not read {p}: {e}')
        elif m_bck == 'stale':
            try:
                obj['bundleCryptKey'] = str(PATTERN_REPLAY[list(PATTERN_REPLAY)[0]]['bundleCryptKey'])
            except Exception:
                obj['bundleCryptKey'] = 'stale'
        elif m_bck == 'garbage':
            obj['bundleCryptKey'] = base64.b64encode(os.urandom(48)).decode()
        elif m_bck == 'mint' or m_bck.startswith('mint:'):
            # bundleCryptKey is AES-256-CBC/PKCS7 over a **32-byte payload** under
            # the client's own session key/IV (ASCII) — the very same cipher as the
            # API bodies, verified by byte-exact re-encryption of a captured token.
            # That is why raw garbage gives 8CN26 (it cannot decrypt at all) and why
            # a real token from another session fails too (wrong key). So we can
            # mint our own, with no official server in the loop:
            #   mint              the client's constant payload (the real thing)
            #   mint:random       32 random bytes (wrong payload -> anti-tamper kill)
            #   mint:zero/zeros   32 zero bytes
            #   mint:<64 hex>     an explicit payload
            #   mint:<text>       sha256(text)
            spec = m_bck.split(':', 1)[1] if ':' in m_bck else 'const'
            if spec in ('', 'const', 'payload'):
                payload = bck_payload()
            elif spec == 'random':
                payload = os.urandom(32)
            elif spec in ('zero', 'zeros'):
                payload = bytes(32)
            elif len(spec) == 64:
                try:
                    payload = bytes.fromhex(spec)
                except ValueError:
                    payload = hashlib.sha256(spec.encode()).digest()
            else:
                payload = hashlib.sha256(spec.encode()).digest()
            try:
                obj['bundleCryptKey'] = base64.b64encode(session_encrypt(payload)).decode()
                log(f'  bck=mint payload={payload.hex()} -> {obj["bundleCryptKey"][:16]}…')
            except Exception as e:
                log(f'  bck=mint failed: {e}')
        elif m_bck == 'empty':
            obj['bundleCryptKey'] = ''
        elif m_bck.startswith('literal:'):
            obj['bundleCryptKey'] = m_bck[len('literal:'):]
        changed.append(f'bundleCryptKey={m_bck}')
    return changed


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


_last_key_timeout = 0.0


def ensure_key(timeout=20.0):
    """Wait for the harvester's per-session key before handling anything.

    The client generates its key at startup and can reach the login within ~3 s
    of the Gadget opening its port, while `_harvest_session.py` deliberately
    waits EZ2_HARVEST_GRACE (15 s) before attaching (an early attach kills the
    process). So the first requests always land before the key exists. Holding
    them here is what makes both a private login and a *forwarded* login work:
    the client is waiting for a response anyway, and its own timeout is the
    limit. Without this, a forwarded login lets the client race ahead to
    `c2s_get_gameinfo`, which we cannot encrypt -> 502 -> 'RESULT : TD3'.
    """
    global _last_key_timeout
    if session_key():
        return True
    # after one full timeout, only probe briefly for the next minute so a dead
    # harvester does not make every request hang for 20 s
    budget = timeout if (time.time() - _last_key_timeout) > 60 else 2.0
    t0 = time.time()
    waited = False
    while time.time() - t0 < budget:
        if session_key():
            log(f'session key arrived after a {time.time() - t0:.1f}s wait')
            return True
        waited = True
        time.sleep(0.25)
    if waited:
        _last_key_timeout = time.time()
        log('still no session key after waiting — is '
            '.venv/bin/python server/_harvest_session.py running?')
    return False


def handle_api(flow: http.HTTPFlow):
    path = flow.request.path.split('?')[0]
    endpoint = path.rstrip('/').split('/')[-1]
    ensure_key()
    req_json, err = decrypt_request(flow.request.raw_content or b'')
    if err:
        log(f'WARN {endpoint}: request not decrypted ({err})')
    else:
        log(f'{endpoint} request: {req_json[:300]}')
        try:
            flow.metadata['ps_req'] = req_json
        except Exception:
            pass

    ep_short = endpoint  # c2s_xxx
    for e in passthrough_set():
        if e in ep_short:
            # forward this endpoint upstream verbatim (the client's request is
            # already encrypted with its own session key, which the real server
            # shares — this is a genuine session for those endpoints only).
            # The response hook logs it before the client sees it.
            log(f'{endpoint}: PASSTHROUGH to upstream (live session)')
            return

    if endpoint == 'c2s_login':
        sk = session_key()
        if sk is None:
            log('ERROR: no session key for login — is _harvest_session.py '
                'running and attached to this game session?')
            flow.response = http.Response.make(
                502, b'private server: no session key',
                {'Content-Type': 'text/plain'})
            return
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
        resp = pattern_response(req_json)
        register_cdn_urls(req_json, resp)
        return respond_api(flow, resp)

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


def cloudfront_shaped_signature():
    """A Signature query-param with the exact shape of a real CloudFront one:
    base64 of a 2048-bit RSA signature (+->-, /->~, ==->__). The client cannot
    verify it without CloudFront's private key, but a malformed shape could
    trip a local sanity check - so we keep the shape honest."""
    b = base64.b64encode(os.urandom(256)).decode()
    return b.translate(str.maketrans('+/=', '-~_'))


def cdn_url(path):
    expires = int(time.time()) + 150
    return (f'https://{CDN_HOST}{path}?Expires={expires}'
            f'&Signature={cloudfront_shaped_signature()}'
            f'&Key-Pair-Id=K2L5B5JS5W46ST')


def cdn_passthrough():
    """Forward CDN cache misses to the official CDN (harvest mode).

    Opt-in via `passthrough_endpoints.txt` containing `cdn`. Without it a miss
    is a 404 and no game-host request ever leaves the machine - which is the
    shipped guarantee (see the addon error path); this knob is the one explicit
    way to let the real CDN serve a chart we do not have yet, so it can be
    recorded and used offline from then on.
    """
    return 'cdn' in passthrough_set() or 'chart' in passthrough_set()


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
    `dump_song.py` produces and `_build_data.py` consumes — so a sweep run needs
    no separate pipeline, and the archive stays the single source of truth for
    what the server can serve. The decrypted `.ez`/`.ezi` are written too, so a
    capture can be audited with `check_charts.py` like any other dump.
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
    # dump_song.py's. Each file stands alone (the key pair is chosen by
    # validation), so there is no ordering requirement; failures are logged,
    # never swallowed - a silent ImportError here cost us a day.
    try:
        sys.path.insert(0, ROOT)
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


def chart_mode():
    """server/data/chart_mode.txt: 'exact' (default) or 'any'.

    'any' serves the best chart we hold *for that song* when the exact
    keymode/difficulty was never captured. The client does not choose the CDN
    path — it downloads whatever URL we return — so one capture per song makes
    every variant of that song loadable (`_coverage.py` counts coverage that
    way). Keep 'exact' while capturing: a miss must go upstream for the body to
    be recorded, and 'any' would answer it locally instead."""
    return (_knob('chart_mode.txt') or 'exact').strip().lower()


def pattern_response(req_json):
    """c2s_get_pattern_file: (musicresourcename, keymode, levelmode) -> URLs."""
    try:
        req = json.loads(req_json) if req_json else {}
    except Exception:
        req = {}
    name = str(req.get('musicresourcename') or req.get('MUSIC_RESOURCE_NAME') or '')
    km = int(req.get('keymode') or req.get('KEYMODE') or 0)
    lm = int(req.get('levelmode') or req.get('LEVELMODE') or 0)
    gm = str(req.get('gamemode') or '')
    want = norm(name)
    # a captured REAL response (real signed URLs + real per-session
    # bundleCryptKey) is the only known-good shape - synthesized responses fail
    # the client's post-parse validation with 8CN26
    key = f"{want}|{km}|{lm}"
    if key in PATTERN_REPLAY:
        log(f'pattern: {name!r} km={km} lm={lm} -> REPLAYED official response')
        obj = dict(PATTERN_REPLAY[key])
        ch = mutate_pattern_response(obj)
        if ch:
            log(f'  MUTATED (replayed): {ch}')
        return obj
    def _pick(pool):
        # prefer the chart captured in the requested gamemode; fall back to one
        # with no recorded gamemode (older dumps) rather than to the other mode
        if gm:
            return (next((c for c in pool if str(c.get('gamemode') or '') == gm), None)
                    or next((c for c in pool if not c.get('gamemode')), None)
                    or pool[0])
        return pool[0]

    exact_pool = [c for c in CHARTS if c['song_norm'] == want and c['keymode'] == km
                  and c['levelmode'] == lm]
    hit = _pick(exact_pool) if exact_pool else None
    how = 'exact'
    if hit is None and chart_mode() == 'any':
        pool = [c for c in CHARTS if c['song_norm'] == want]
        if pool:
            # prefer the same keymode (fewest lane mismatches), then the 4K EZ
            # variant the Lounge serves, then anything captured for the song
            pick = (next((c for c in pool if c['keymode'] == km), None)
                    or next((c for c in pool if c['keymode'] == 1 and c['levelmode'] == 1), None)
                    or pool[0])
            hit, how = pick, 'any-variant'
    if hit is None:
        have = sorted({c['song_norm'] for c in CHARTS})
        log(f'pattern: NO replay/chart for {name!r} keymode={km} levelmode={lm} '
            f'(known songs: {have})')
        return {'result': 0}
    resp = {
        'final_url_ez': cdn_url(hit['ez_path']),
        'final_url_ezi': cdn_url(hit['ezi_path']),
        'bundleCryptKey': bundle_crypt_key(),
        'result': 1,
    }
    log(f"pattern: {name!r} km={km} lm={lm} -> {how} "
        f"{hit['keymode_dir']}/{hit['levelmode_dir']}")
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


_warned_no_key = False


def respond_api(flow, obj):
    global _warned_no_key
    try:
        body = encrypt_response(obj)
    except RuntimeError as e:
        # almost always: the Frida harvester is not running, so the client's
        # per-session key is unknown and NOTHING can be encrypted for it.
        if not _warned_no_key:
            _warned_no_key = True
            log('NO SESSION KEY — cannot encrypt any API response. Start the '
                'bridge: .venv/bin/python server/_harvest_session.py (or forward '
                'this endpoint too, e.g. passthrough_endpoints.txt = '
                'login,gameinfo,myinfo,pattern).')
        flow.response = http.Response.make(
            502,
            b'private server: no session key - run server/_harvest_session.py',
            {'Content-Type': 'text/plain'})
        return
    flow.response = http.Response.make(
        200, body, upstream_like_headers())


def handle_rank(flow: http.HTTPFlow):
    q = flow.request.query.get('data', '')
    body = flow.request.raw_content or b''
    # log EVERY rank request: the game also talks to this host on a raw,
    # un-proxied TLS channel (custom client, 3.37.247.33:443, bypasses the
    # proxy) — see server/README.md, that is where the session/bundleCryptKey
    # check lives. Anything appearing here after a hosts redirect is that
    # channel, and its exact shape is what a fully-offline server must answer.
    log(f'rank {flow.request.method} {flow.request.path[:70]} '
        f'data={q[:110]!r} body={len(body)}B')
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
        body = b''
    flow.response = http.Response.make(
        200, body, {'Content-Type': 'application/json'})


def handle_cdn(flow: http.HTTPFlow):
    p = flow.request.path.split('?')[0]
    rel = CDN_PATHS.get(p)
    if rel is None:
        if cdn_passthrough():
            # harvest: no local copy, so let the official CDN answer and we
            # record the body on the way back (capture_cdn_response)
            log(f'CDN MISS {p} -> upstream (harvest)')
            return
        log(f'CDN MISS {p}')
        flow.response = http.Response.make(404, b'', {'Content-Type': 'text/plain'})
        return
    log(f'CDN HIT {p}')
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

    def response(self, flow: http.HTTPFlow):
        """CDN bodies coming back from upstream are recorded; for a
        PASSTHROUGH API endpoint the upstream response is logged (so its exact
        field set is visible), the mutate_* knobs are applied to a pattern
        response, and everything else is let through untouched."""
        host = (flow.request.host or '').lower()
        if host == CDN_HOST:
            try:
                capture_cdn_response(flow)
            except Exception:
                log('CDN capture error\n' + traceback.format_exc())
            return
        if host != API_HOST or flow.response is None:
            return
        ep = flow.request.path.rsplit('/', 1)[-1]
        eps = passthrough_set()
        if not any(e in ep for e in eps):
            return
        try:
            obj = decrypt_api_body(flow.response.content)
            if obj is None:
                log(f'{ep}: upstream response did not decrypt (stale session '
                    'key? — was the login forwarded too?)')
                return
            save_upstream(ep, obj)
            ch = None
            if ep == 'c2s_get_pattern_file' and mutation_requested():
                ch = mutate_pattern_response(obj)
                if ch:
                    flow.response.content = encrypt_response(obj)
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

    def error(self, flow: http.HTTPFlow):
        if (flow.request.host or '').lower() in (API_HOST, RANK_HOST, CDN_HOST):
            log(f'FLOW ERROR {flow.request.method} {flow.request.path}: '
                f'{flow.error.msg if flow.error else "?"}')


addons = [PrivateServer()]
