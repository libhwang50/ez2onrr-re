"""
EZ2ON REBOOT:R — private-server game logic (standalone, transport-neutral).

This module is the offline server core: the three game hosts are answered
entirely server-side, with no upstream contact.

    game1-play.ez2game.co.kr   API   (AES-256-CBC/PKCS7, zf session key)
    game1-rank.ez2game.co.kr   rank  (plaintext GETs)
    game1-cdn.ez2game.co.kr    CDN   (chart/index ciphertext blobs)

Run it with the standalone transport (`server/app.py`) behind the client-side
relay (`server/_relay.py`).  The handlers only touch the small request/response
surface supplied by `_flowshim`, so this body of code is transport-neutral.

Protocol notes (all verified against captures — see §3.1):
  * API request  body: form-encoded; the `data` field holds
    urlenc(b64( magic[6]=d3ad76d3adb8 || AES-CBC-PKCS7(json) )). `c2s_login`
    additionally carries `ticket` and `identity` fields.
  * API response body: b64( AES-CBC-PKCS7(json) )            (no magic)
  * key/IV = ASCII bytes of zf.aes_key (32) / zf.aes_iv (16), generated
    client-side per session (zf.gnf: RNGCryptoServiceProvider -> hex).
    The patcher version.dll hands them over in the RSA login block; the memory
    scanner writes them to server/session_key.json for an unpatched client.

Game-host requests are NEVER forwarded upstream by this module.  Chart capture
from the official CDN (the sweep) is a separate mitmproxy addon that wraps this
core: `server/re/_capture_addon.py`.
"""
from __future__ import annotations

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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _flowshim  # noqa: E402
import _rsa  # noqa: E402
import _sessions  # noqa: E402
import _store  # noqa: E402
import _auth  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# data/ holds the RSA key, the templates and store.db; overridable so a container
# can mount it anywhere (server/README.md, docker-compose.yml).
DATA = os.environ.get('EZ2_DATA') or os.path.join(ROOT, 'server', 'data')
KEYFILE = os.environ.get('EZ2_KEYFILE') or os.path.join(ROOT, 'server', 'session_key.json')
# multi-user: steamid -> Session (key/iv), plus an addr cache; see _sessions.py
SESSIONS = _sessions.Registry()
# per-user progression (memberinfo + clearlist); lives under git-ignored data/
STORE = _store.Store(os.path.join(DATA, 'store.db'))
# the account whose captured progression seeds a fresh store (data/owner.txt)
OWNER = '76561199429391557'
try:
    LOG = open(os.environ.get('EZ2_LOG')
               or os.path.join(ROOT, 'server', 'pserver.log'), 'a', buffering=1)
except OSError:
    LOG = sys.stdout

API_HOST = 'game1-play.ez2game.co.kr'
RANK_HOST = 'game1-rank.ez2game.co.kr'
CDN_HOST = 'game1-cdn.ez2game.co.kr'
MAGIC = bytes.fromhex('d3ad76d3adb8')

TEMPLATES = {}
CDN_PATHS = {}
# paths the last pattern responses pointed at: {path: {song,keymode,levelmode,
# gamemode,kind}} - so a forwarded CDN body can be filed under the chart it is
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
    global OWNER
    p = os.path.join(DATA, 'owner.txt')
    if os.path.exists(p):
        OWNER = open(p).read().strip() or OWNER
    seed_owner()
    log(f'data loaded: templates={sorted(TEMPLATES)} cdn={len(CDN_PATHS)} '
        f'charts={len(CHARTS)} '
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

# The 32-byte payload constant of the current client build (EZ2ON REBOOT:R,
# 2026.09.04.001). `bundleCryptKey` is AES-256-CBC/PKCS7 of this constant under
# the client's live session key; the client decrypts the served token and
# compares it with its own copy. It is a **build-time constant of the client**,
# not session material — so this literal is all that is needed to mint a valid
# token. It is embedded here (rather than only in the git-ignored data/ dir) so
# a published server works offline out of the box; a future game update can
# change it, in which case `server/data/bck_payload.hex` or a fresh capture
# overrides it.
DEFAULT_BCK_PAYLOAD = bytes.fromhex(
    'd3163d646fedbbcc07a752f663fcd4cf06f5f9eedbadcc70244f20c82ad76922')


def bck_payload():
    """The 32-byte plaintext the client expects inside bundleCryptKey.

    bundleCryptKey is AES-256-CBC/PKCS7(32-byte payload) under the client's live
    session key/IV — the same cipher as the API bodies. The payload is a
    **build-time constant of the client**, not session material: two captured
    tokens from different key material decrypted to the same 32 bytes. So the
    server does not need an official response at all — it encrypts this constant.

    Order: server/data/bck_payload.hex (per-build override), else derive it from
    the last captured upstream pattern response (works when the capture is from
    the same session key — authoritative after a game update), else the
    hardcoded constant for the known build.
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
    return DEFAULT_BCK_PAYLOAD


def write_session_key(key: bytes, iv: bytes, steamid: str | None = None):
    """Persist the live session key/iv (same file the Frida harvester writes)."""
    tmp = KEYFILE + '.tmp'
    rec = {'aes_key': key.decode('ascii', 'replace'),
           'aes_iv': iv.decode('ascii', 'replace'),
           'source': 'rsa', 't': time.time()}
    if steamid:
        rec['steamid'] = steamid
    json.dump(rec, open(tmp, 'w'))
    os.replace(tmp, KEYFILE)
    log(f'session key <- RSA login: {key!r} / {iv!r}'
        + (f' (steamid {steamid})' if steamid else ''))


def try_login_rsa(body: bytes, addr: str | None = None):
    """Frida-free hand-off: RSA-decrypt `c2s_login.data` under our private key.

    **Confirmed live 2026-09-24**: the login `data` field is one 2048-bit
    (256 B) RSA block whose plaintext is the client's login JSON
    `{"steamid","appid","version","key","iv"}` — so it carries the session
    key/IV *and* the identity (§3.1).  The drop-in patcher rewrites
    `zf.publicKey` to ours, so this recovers both with no Frida and no memory
    scan.  We always attempt the decode (the key rotates within a launch), bind
    the result in the session registry, and return that `Session`.  On failure
    (unpatched client) fall back to this address's registry entry, then to the
    legacy single-client `session_key.json`.  Never raises.
    """
    have = session_key()
    fallback = lambda: SESSIONS.by_addr(addr) or legacy_session()
    enc = parse_form(body)
    if not enc:
        return fallback()
    try:
        raw = base64.b64decode(enc + '=' * (-len(enc) % 4))
    except Exception as e:
        log(f'login RSA: bad base64 ({e})')
        return fallback()
    try:
        with open(os.path.join(DATA, 'login_data.bin'), 'wb') as f:
            f.write(raw)
    except Exception:
        pass
    if len(raw) not in (128, 256, 384, 512):
        log(f'login RSA: data is {len(raw)}B, not a single RSA block '
            f'(head={raw[:6].hex()})')
        return fallback()
    label, pt = _rsa.decrypt(raw)
    if pt is None:
        log('login RSA: block is not encrypted under our public key — is the '
            'patcher version.dll active (version=n,b)?')
        return fallback()
    try:
        with open(os.path.join(DATA, 'login_rsa_plain.bin'), 'wb') as f:
            f.write(pt)
    except Exception:
        pass
    key, iv = _rsa.split_key_iv(pt)
    steamid = _rsa.login_steamid(pt)
    log(f'login RSA ({label}): {len(pt)}B json steamid={steamid} '
        f'key={key!r} iv={iv!r}')
    if key is not None and iv is not None:
        if have and (key, iv) != (have[0], have[1]):
            log('login RSA: key ROTATED vs session_key.json — adopting the '
                'login block (authoritative for this session)')
        write_session_key(key, iv, steamid)
        return SESSIONS.bind(steamid, key, iv, addr, source='rsa')
    log('login RSA: plaintext is not a key/iv carrier; see '
        'server/data/login_rsa_plain.bin')
    return fallback()


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


def legacy_session():
    """The single-client fallback: whatever the harvester last wrote."""
    sk = session_key()
    if sk is None:
        return None
    key, iv, _age = sk
    return _sessions.Session(None, key, iv, source='file')


def flow_addr(flow):
    """The client's source IP (for the addr->session fast path), or ''."""
    try:
        peer = flow.client_conn.peername
        return peer[0] if peer else ''
    except Exception:
        return ''


def seed_owner():
    """Import the captured progression once, for the owner account only."""
    tpl = TEMPLATES.get('myinfo')
    if not OWNER or not isinstance(tpl, dict) or not tpl.get('clearlist'):
        return
    try:
        if STORE.player(OWNER) is None or not STORE.clearlist(OWNER):
            n = STORE.seed_myinfo(OWNER, tpl)
            log(f'store: seeded {n} cleared variants for owner {OWNER}')
    except Exception:
        log('store: owner seed failed\n' + traceback.format_exc())


def parse_form(body: bytes):
    """The API posts form fields (data=..., and ticket=/identity= on login).
    Returns the url-decoded `data` value, or None."""
    text = body.decode('utf-8', 'replace')
    for part in text.split('&'):
        k, _, v = part.partition('=')
        if k == 'data':
            return urllib.parse.unquote(v)
    return None


def client_token(flow):
    """The caller's bearer token (_auth.py): relay header `X-EZ2-Token`, an
    `Authorization: Bearer`, or the configured local token file (single-machine
    use — the public deployment's relay supplies the header instead)."""
    try:
        h = flow.request.headers
    except Exception:
        h = {}
    tok = h.get('x-ez2-token')
    if not tok:
        auth = h.get('authorization') or ''
        if auth[:7].lower() == 'bearer ':
            tok = auth[7:].strip()
    if not tok:
        p = _auth.load().get('token_file') or ''
        if p:
            try:
                tok = open(p).read().strip() or None
            except Exception:
                tok = None
    return tok or None


def decrypt_request(body: bytes, sess=None):
    """API request -> (json_text, error) under `sess`. Never raises."""
    enc = parse_form(body)
    if enc is None:
        return None, 'no data= field'
    try:
        raw = base64.b64decode(enc + '=' * (-len(enc) % 4))
    except Exception as e:
        return None, f'bad base64: {e}'
    if raw[:6] != MAGIC:
        return None, f'bad magic {raw[:6].hex()}'
    if sess is None:
        return None, 'no session key'
    key, iv = sess.key, sess.iv
    try:
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        pt = pkcs7_unpad(dec.update(raw[6:]) + dec.finalize())
        return pt.decode('utf-8', 'replace'), None
    except Exception as e:
        return None, f'decrypt failed (stale session key?): {e}'


def decrypt_with(body, sess):
    """The request body iff `sess` decrypts it, else None (magic + padding)."""
    return decrypt_request(body, sess)[0]


def resolve_session(body, addr):
    """Attribute a magic||AES API request to a user.

    Returns (session, json_text, error).  Order: the address's cached session,
    then every known key by trial decryption, then the legacy single-client
    harvester file.  The magic (`d3ad76d3adb8`) plus PKCS#7 padding makes a
    wrong key fail cleanly, so trial decryption is safe for a handful of users —
    and it survives NAT and a client that reconnects on a new port.
    """
    s = SESSIONS.by_addr(addr) if addr else None
    if s is not None:
        txt = decrypt_with(body, s)
        if txt is not None:
            return s, txt, None
    for s in SESSIONS.all():
        txt = decrypt_with(body, s)
        if txt is not None:
            if addr and s.steamid:
                SESSIONS.note_addr(addr, s.steamid)
            return s, txt, None
    g = legacy_session()
    if g is not None:
        txt = decrypt_with(body, g)
        if txt is not None:
            return g, txt, None
    if len(SESSIONS) or g is not None:
        return None, None, 'no known session key decrypts this request'
    return None, None, 'no session key (no login seen)'


def session_encrypt(raw: bytes, sess=None) -> bytes:
    """AES-256-CBC/PKCS7 under the client's own session key (raw ciphertext).

    Same primitive the API bodies use; `bundleCryptKey` is this over a 32-byte
    payload (see the `mint` bck mode)."""
    if sess is None:
        raise RuntimeError('no session key')
    key, iv = sess.key, sess.iv
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(pkcs7_pad(raw)) + enc.finalize()


def encrypt_response(json_obj, sess=None) -> bytes:
    pt = json.dumps(json_obj, separators=(',', ':'), ensure_ascii=False).encode()
    return base64.b64encode(session_encrypt(pt, sess))


def decrypt_api_body(body: bytes, sess=None):
    """An upstream API response body -> json object, or None. Never raises.

    Same cipher as encrypt_response (b64 of AES-CBC/PKCS7 under the client's
    own session key — upstream encrypts with the key the client uses)."""
    if sess is None:
        return None
    key, iv = sess.key, sess.iv
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


def mutate_pattern_response(obj, defaults=True, sess=None):
    """Apply the knob files, falling back to the fully-offline defaults.

    With `defaults=True` (the local-serving path) an absent knob means the
    offline recipe: mint a fresh `Expires` (the CloudFront signature is never
    verified) and mint the `bundleCryptKey` knowledge proof from the client's
    live session key. `defaults=False` is used by the capture addon's upstream
    response hook, where the upstream already minted both and a rewrite would
    break the real CloudFront signature.

    A knob of `off`/`none` disables that piece of the default. Returns a list
    of applied changes, or None."""
    if not isinstance(obj, dict):
        return None
    m_url, m_bck = _knob('mutate_urls.txt'), _knob('mutate_bck.txt')
    if defaults:
        m_url = m_url or 'now'
        m_bck = m_bck or 'mint'
    if m_url in ('off', 'none'):
        m_url = ''
    if m_bck in ('off', 'none'):
        m_bck = ''
    if not (m_url or m_bck):
        return None
    changed = []
    if m_url:
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
                obj['bundleCryptKey'] = base64.b64encode(session_encrypt(payload, sess)).decode()
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
            '.venv/bin/python server/re/_harvest_session.py running?')
    return False


def bind_session(flow: '_flowshim.Flow', endpoint, body, addr):
    """Attribute an API request to a session and stash it on the flow.

    The login block is RSA under our public key (patcher `version.dll`) and
    carries the session key/IV *and* the SteamID; it creates (or refreshes) the
    user's session.  Every other API request carries no SteamID, so it is
    attributed by address, then by trial decryption against the known keys.
    Shared with the capture addon, which needs the session to decrypt an
    upstream (forwarded) response.  Returns (session, request_json).
    """
    if endpoint == 'c2s_login':
        sess = try_login_rsa(body, addr)
        if sess is None and ensure_key():
            sess = legacy_session()
        req_json, err = None, None
    else:
        sess, req_json, err = resolve_session(body, addr)
    try:
        flow.metadata['ps_session'] = sess
    except Exception:
        pass
    if err:
        log(f'WARN {endpoint}: request not decrypted ({err})')
    elif req_json is not None:
        log(f'{endpoint} request: {req_json[:300]}')
        try:
            flow.metadata['ps_req'] = req_json
        except Exception:
            pass
    return sess, req_json


def handle_api(flow: '_flowshim.Flow'):
    path = flow.request.path.split('?')[0]
    endpoint = path.rstrip('/').split('/')[-1]
    addr = flow_addr(flow)
    body = flow.request.raw_content or b''
    sess, req_json = bind_session(flow, endpoint, body, addr)

    if endpoint == 'c2s_login':
        if sess is None:
            log('ERROR: no session key for login — patcher version.dll not '
                'active on the client, and no harvested key available')
            flow.response = _flowshim.make(
                502, b'private server: no session key',
                {'Content-Type': 'text/plain'})
            return
        # Resolve who this is (see _auth.py).  In open mode the claimed
        # SteamID is the account (backwards compatible); in token mode a
        # server-issued bearer token decides, with a configurable guest tier.
        ident = _auth.identify(STORE, sess.steamid, client_token(flow))
        if ident.kind in ('denied', 'banned'):
            log(f'login denied (claimed={sess.steamid}): {ident.reason}')
            return respond_api(flow, {'result': 0}, sess)
        sess.steamid = ident.account_id
        sess.persist = ident.persist
        sess.kind = ident.kind
        log(f'login identity: {ident}')
        log(f'login: serving template to {sess.label()}')
        tpl = TEMPLATES.get('login')
        if tpl is None:
            return respond_api(flow, {'result': 0}, sess)
        return respond_api(flow, login_response(tpl, sess), sess)

    if endpoint == 'c2s_get_gameinfo':
        tpl = TEMPLATES.get('gameinfo')
        if tpl is None:
            return respond_api(flow, {'result': 0}, sess)
        return respond_api(flow, tpl, sess)

    if endpoint == 'c2s_get_myinfo':
        tpl = TEMPLATES.get('myinfo')
        if tpl is None:
            return respond_api(flow, {'result': 0}, sess)
        return respond_api(flow, myinfo_response(tpl, sess), sess)

    if endpoint == 'c2s_get_userinfo':
        return respond_api(flow, userinfo_response(req_json, sess), sess)

    if endpoint == 'c2s_get_pattern_file':
        resp = pattern_response(req_json, sess)
        # Missing chart: return 404 instead of {result:0} to prevent the game from hanging
        if isinstance(resp, dict) and resp.get('result') == 0:
            try:
                req = json.loads(req_json) if req_json else {}
            except Exception:
                req = {}
            name = str(req.get('musicresourcename') or req.get('MUSIC_RESOURCE_NAME') or '')
            km = int(req.get('keymode') or req.get('KEYMODE') or 0)
            lm = int(req.get('levelmode') or req.get('LEVELMODE') or 0)
            log(f'pattern: {name!r} km={km} lm={lm} -> 404 NOT FOUND')
            flow.response = _flowshim.make(404, b'', {'Content-Type': 'text/plain'})
            return
        return respond_api(flow, resp, sess)

    if endpoint == 'c2s_set_game_clear':
        # real DTO (metadata-mined): {level, exp, nextExp, result}; the request
        # carries musicid/keymode/levelmode + the play's statistics, which we
        # fold into the per-user store so get_myinfo reflects them next session.
        # A non-persistent guest never reaches the store or a leaderboard.
        if sess is not None and sess.persist and sess.steamid and req_json:
            try:
                r = json.loads(req_json)
                mid = int(r.get('musicid') or 0)
                km = int(r.get('keymode') or 0)
                lm = int(r.get('levelmode') or 0)
                if mid and km and lm:
                    STORE.record_clear(
                        sess.steamid, mid, km, lm,
                        lamp=int(r.get('lamp') or 0),
                        score=int(float(r.get('score') or 0)),
                        rate=float(r.get('rate') or 0.0),
                        combo=int(r.get('combo') or 0),
                        kool=int(r.get('kool') or 0),
                        cool=int(r.get('cool') or 0),
                        good=int(r.get('good') or 0),
                        miss=int(r.get('miss') or 0),
                        fail=int(r.get('fail') or 0))
                    log(f'set_game_clear: stored {sess.steamid} music={mid} '
                        f'km={km} lm={lm} score={r.get("score")}')
            except Exception as e:
                log(f'set_game_clear: could not store play ({e})')
        cfg = os.path.join(DATA, 'set_game_clear.json')
        p = STORE.player(sess.steamid) if (sess and sess.persist and sess.steamid) else None
        if p is not None:
            tpl = {'level': int(p['level']), 'exp': int(p['exp']),
                   'nextExp': int(p['next_exp']), 'result': 1}
        elif sess is not None and sess.steamid and not sess.persist:
            tpl = {'level': 1, 'exp': 0, 'nextExp': 0, 'result': 1}
        elif sess is not None and sess.steamid:
            tpl = {'level': 1, 'exp': 0, 'nextExp': 0, 'result': 1}
        elif os.path.exists(cfg):
            tpl = json.load(open(cfg))
        else:
            prof = get_profile()
            tpl = {'level': int(prof.get('LEVEL', 1)),
                   'exp': int(prof.get('EXP', 0)),
                   'nextExp': int(prof.get('NEXT_EXP', 0)), 'result': 1}
        return respond_api(flow, tpl, sess)

    log(f'UNKNOWN api endpoint {path} — returning generic result')
    return respond_api(flow, {'result': 1}, sess)


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


def chart_mode():
    """server/data/chart_mode.txt: 'exact' (default) or 'any'.

    'any' serves the best chart we hold *for that song* when the exact
    keymode/difficulty was never captured. The client does not choose the CDN
    path — it downloads whatever URL we return — so one capture per song makes
    every variant of that song loadable (`_coverage.py` counts coverage that
    way). But it is **not a safe default**: a chart's notes are assigned to
    lanes per keymode/difficulty, so serving a 5K SHD chart for a 6K EZ request
    plays the wrong lane assignment (the game just ignores lanes beyond the
    selected key mode). Keep 'exact' unless you deliberately want that.

    'any' is also wrong while capturing: a miss must go upstream for the body to
    be recorded, and 'any' would answer it locally instead. `_exp.py harvest`
    selects 'exact' automatically."""
    return (_knob('chart_mode.txt') or 'exact').strip().lower()


def pattern_response(req_json, sess=None):
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
        ch = mutate_pattern_response(obj, sess=sess)
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
        if gm:
            # the .ezi is NOT always one per song: on some songs the keysound index
            # differs by keymode (ultimatum: {4K,6K} share one, {5K,8K} another),
            # so stay inside the requested gamemode when we can
            same_gm = [c for c in pool if str(c.get('gamemode') or '') == gm]
            pool = same_gm or pool
        if pool:
            # a chart record always pairs its own .ez with its own .ezi, so any
            # choice here is internally consistent; prefer the same keymode (no
            # lane mismatch), then the 4K EZ variant the Lounge serves
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
    ch = mutate_pattern_response(resp, sess=sess)
    if ch:
        log(f'  MUTATED (chart): {ch}')
    log(f"pattern: {name!r} km={km} lm={lm} -> {how} "
        f"{hit['keymode_dir']}/{hit['levelmode_dir']}")
    return resp


def bundle_crypt_key():
    p = os.path.join(DATA, 'bundleCryptKey.txt')
    if os.path.exists(p):
        return open(p).read().strip()
    return '0' * 96


def login_response(tpl, sess):
    """Rewrite the captured login template's `member` to the caller.

    The template is the owner's real login response, so serving it verbatim
    leaks the owner's SteamID/nickname to every other account.  Per-user fields
    come from the store (persistent callers) or are blanked (guests).
    """
    try:
        d = json.loads(json.dumps(tpl))
    except Exception:
        d = dict(tpl)
    m = d.get('member')
    sid = sess.steamid if sess else None
    if isinstance(m, dict) and sid:
        m['STEAM_ID'] = str(sid)
        p = STORE.player(sid) if (sess is None or sess.persist) else None
        m['LEVEL'] = int(p.get('level') or 1) if p else 1
        m['RATING'] = float(p.get('rating') or 0.0) if p else 0.0
        if sid == OWNER:
            apply_profile(m)
        else:
            m['NICKNAME'] = 'Player'
            m['PLAY_COUNT'] = 0
            m['WIN_COUNT'] = 0
            m['LOSE_COUNT'] = 0
    return d


def default_myinfo(tpl, steamid):
    """A read-only default profile for a guest (no store row is created)."""
    try:
        mi = json.loads(json.dumps(tpl))
    except Exception:
        mi = dict(tpl)
    mi['memberinfo'] = STORE.memberinfo(steamid) if steamid else mi.get('memberinfo', {})
    mi['clearlist'] = STORE.clearlist(steamid) if steamid else []
    mi.setdefault('course_clearlist', [])
    return mi


def myinfo_response(tpl, sess):
    """Build `c2s_get_myinfo` from the per-user store.

    A persistent caller gets/creates its store row; a non-persistent guest is
    served a default profile **without** writing anything, so it cannot appear
    on a leaderboard.  With no identity (the legacy harvester path) the captured
    template is served unchanged, and `profile.json` overrides still apply.
    """
    steamid = sess.steamid if sess else None
    persist = sess is None or bool(sess.persist)
    if steamid and persist:
        STORE.touch_player(steamid)
        try:
            mi = json.loads(json.dumps(tpl))
        except Exception:
            mi = dict(tpl)
        mi['memberinfo'] = STORE.memberinfo(steamid)
        mi['clearlist'] = STORE.clearlist(steamid)
        mi.setdefault('course_clearlist', [])
        if steamid == OWNER:
            apply_profile(mi)
        return mi
    if steamid:
        return default_myinfo(tpl, steamid)
    try:
        mi = json.loads(json.dumps(tpl))
    except Exception:
        mi = dict(tpl)
    apply_profile(mi)
    return mi


def userinfo_response(req_json, sess=None):
    """c2s_get_userinfo: {"appid":...,"steamId":[UInt64,...]} — the leaderboard
    profile fetch (up to ~10 players at once).

    **Shape solved from the IL2CPP metadata** (2026-09-24). The string table
    groups the DTOs by class, and `c2s_get_userinfo` is
    `{memberinfo: [{STEAM_ID, LEVEL, RATING}, …], result}` — the entry is *not*
    the full `memberinfo` struct of `c2s_get_myinfo`. There is no nickname field
    anywhere in the client (a plain `grep NICK` over global-metadata.dat is
    empty), so the earlier guess carried invented fields. The official capture
    (`mitm_parsed/replay_0922`) cannot be decrypted — the session key rotated and
    was never kept — but the field set is not a guess any more.

    `data/userinfo_entry.json` may override the per-entry template."""
    try:
        req = json.loads(req_json) if req_json else {}
    except Exception:
        req = {}
    ids = req.get('steamId') or req.get('SteamId') or []
    if not isinstance(ids, list):
        ids = [ids]
    tpl_p = os.path.join(DATA, 'userinfo_entry.json')
    tpl = json.load(open(tpl_p)) if os.path.exists(tpl_p) else {
        'STEAM_ID': '0', 'LEVEL': 1, 'RATING': 0.0,
    }
    entries = []
    for sid in ids:
        e = dict(tpl)
        e['STEAM_ID'] = str(sid)
        p = STORE.player(sid)
        if p:
            e['LEVEL'] = int(p.get('level') or 0)
            e['RATING'] = float(p.get('rating') or 0.0)
        entries.append(e)
    log(f'get_userinfo: {len(entries)} profile(s) served '
        f'(entry = STEAM_ID/LEVEL/RATING)')
    return {'memberinfo': entries, 'result': 1}


_warned_no_key = False


def respond_api(flow, obj, sess=None):
    global _warned_no_key
    if sess is None:
        try:
            sess = flow.metadata.get('ps_session')
        except Exception:
            sess = None
    try:
        body = encrypt_response(obj, sess)
    except RuntimeError:
        # No key for this client: either its login was never seen (so the
        # session registry is empty for it) or the harvester is not running.
        if not _warned_no_key:
            _warned_no_key = True
            log('NO SESSION KEY for a client — cannot encrypt the API response. '
                'Install the patcher version.dll (client/patcher), or start '
                'the harvester: /usr/bin/python server/re/_harvest_mem.py.')
        flow.response = _flowshim.make(
            502,
            b'private server: no session key - run server/re/_harvest_session.py',
            {'Content-Type': 'text/plain'})
        return
    flow.response = _flowshim.make(
        200, body, upstream_like_headers())


def rank_delay():
    """Seconds to hold the pre-login battle-server lookup (server/data/rank_delay.txt)."""
    try:
        v = float(open(os.path.join(DATA, 'rank_delay.txt')).read().strip())
        return max(0.0, min(v, 60.0))
    except Exception:
        return float(os.environ.get('EZ2_RANK_DELAY', '0') or 0)


def handle_rank(flow: '_flowshim.Flow'):
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
        # Key-patch window: this request immediately precedes the login block
        # build.  Holding the response gives a host-side patcher time to swap
        # zf.publicKey / the cached modulus before the client encrypts.  Read
        # per request so it can be changed without a restart; 0 disables it.
        delay = rank_delay()
        if delay:
            log(f'rank: holding get_battle_server_ip {delay:.0f}s '
                f'(client key-patch window)')
            time.sleep(delay)
        body = BATTLE_SERVER.encode()
    elif q.startswith('get') and q != 'get_battle_server_ip' and arg[3:].isdigit():
        body = leaderboard_body(q)
    elif q.startswith('plf'):
        log(f'score upload: {urllib.parse.unquote(q)[:200]}')
        body = b''
    else:
        # rating / totalranking / getcoursedata / misc — empty matches the
        # official servers' own responses
        body = b''
    flow.response = _flowshim.make(
        200, body, {'Content-Type': 'application/json'})


def leaderboard_body(q):
    """Compute the `rank,score,steamid,…` stream for a leaderboard query.

    Query: `get<music_id><keymode><levelmode>[,<page>[,<steamid>]]`.  Scores come
    from the per-user store; when the variant has no local scores at all we fall
    back to the real captured CSV (so a song nobody here has played still looks
    populated) and then to the static sample.
    """
    parts = q.split(',')
    key = parts[0][3:]
    if len(key) < 3 or not key[:-2].isdigit():
        return RANK_CSV_SAMPLE.encode()
    music_id, km, lm = int(key[:-2]), int(key[-2]), int(key[-1])
    page = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    steamid = parts[2] if len(parts) > 2 else None
    rows, total = STORE.leaderboard(music_id, km, lm, page=page, steamid=steamid)
    if total:
        out = []
        for rank, sid, score in rows:
            out += [str(rank), str(score), str(sid)]
        log(f'leaderboard get{music_id}{km}{lm} page={page} -> {len(rows)} rows '
            f'(of {total})')
        return ','.join(out).encode()
    csv = os.path.join(DATA, 'rank_csv', q.replace(',', '_') + '.csv')
    if os.path.exists(csv):
        return open(csv, 'rb').read()
    return RANK_CSV_SAMPLE.encode()


def handle_cdn(flow: '_flowshim.Flow'):
    p = flow.request.path.split('?')[0]
    rel = CDN_PATHS.get(p)
    if rel is None:
        log(f'CDN MISS {p}')
        flow.response = _flowshim.make(404, b'', {'Content-Type': 'text/plain'})
        return
    log(f'CDN HIT {p}')
    data = open(os.path.join(ROOT, rel), 'rb').read()
    flow.response = _flowshim.make(
        200, data, {'Content-Type': 'application/octet-stream'})
