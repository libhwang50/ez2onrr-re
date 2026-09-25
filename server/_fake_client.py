#!/usr/bin/env python3
"""Synthetic second client — exercise the multi-user server with no game.

The private server keys each session off the SteamID inside the RSA-wrapped
login JSON, so a fake client only has to reproduce four things (all of which the
real client does, see §3.1):

  1. generate a 32-hex key / 16-hex IV,
  2. RSA-encrypt `{"steamid","appid","version","key","iv"}` under the server's
     public key and post it as the login `data` field,
  3. speak `data=<b64( d3ad76d3adb8 || AES-CBC-PKCS7(json) )>` from then on,
  4. decrypt responses the same way (plain `b64(AES(json))`).

That is enough to create a brand-new user, fetch its myinfo, record a play and
read the shared leaderboard — so the whole multi-user path can be tested without
a second Steam account or a second game copy.  It is also the skeleton for the
"register once, get a server-issued token" auth a public server will need.

    python3 server/_fake_client.py 76561190000000001
    python3 server/_fake_client.py 76561190000000002 --play --score 1012345
    python3 server/_fake_client.py 76561190000000001 --leaderboard

The proxy is the running mitmdump (`127.0.0.1:8080`) or `--remote` points at a
standalone `server/app.py`; no real server is contacted.
"""
import argparse
import base64
import json
import os
import secrets
import sys
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _rsa  # noqa: E402

from cryptography.hazmat.primitives.asymmetric import padding  # noqa: E402
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402

API_HOST = 'game1-play.ez2game.co.kr'
RANK_HOST = 'game1-rank.ez2game.co.kr'
APPID = '1477590'
MAGIC = bytes.fromhex('d3ad76d3adb8')
PROXY = os.environ.get('PSERVER_PROXY', 'http://127.0.0.1:8080')
# Direct-to-deployment mode: POST straight at a standalone server (server/app.py)
# with an X-EZ2-Host header, no local mitmproxy.  PSERVER_REMOTE=https://ez2.example.com
REMOTE = (os.environ.get('PSERVER_REMOTE') or '').rstrip('/')
INSECURE = os.environ.get('PSERVER_INSECURE', '') not in ('', '0', 'false', 'False')


def _pkcs7(b: bytes) -> bytes:
    n = 16 - len(b) % 16
    return b + bytes([n]) * n


def _unpad(b: bytes) -> bytes:
    return b[:-b[-1]]


def _aes_enc(pt: bytes, key: bytes, iv: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return c.update(_pkcs7(pt)) + c.finalize()


def _aes_dec(ct: bytes, key: bytes, iv: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return _unpad(c.update(ct) + c.finalize())


def _opener(host, headers):
    """An opener for the direct remote, or the local mitmproxy."""
    if REMOTE:
        headers['X-EZ2-Host'] = host
        url = REMOTE + '{path}'
        if INSECURE:
            import ssl
            return url, urllib.request.build_opener(
                urllib.request.HTTPSHandler(
                    context=ssl._create_unverified_context()))
        return url, urllib.request.build_opener()
    return f'http://{host}' + '{path}', urllib.request.build_opener(
        urllib.request.ProxyHandler({'http': PROXY, 'https': PROXY}))


def _post(host: str, path: str, form: dict, token: str = None) -> bytes:
    body = urllib.parse.urlencode(form).encode()
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    if token:
        headers['X-EZ2-Token'] = token
    url, op = _opener(host, headers)
    req = urllib.request.Request(url.format(path=path), data=body, headers=headers)
    with op.open(req, timeout=15) as r:
        return r.read()


def _get(host: str, path: str, token: str = None) -> bytes:
    headers = {'X-EZ2-Token': token} if token else {}
    url, op = _opener(host, headers)
    req = urllib.request.Request(url.format(path=path), headers=headers)
    with op.open(req, timeout=15) as r:
        return r.read()


class FakeClient:
    def __init__(self, steamid: str, version: str = '2026.09.04.001',
                 token: str = None):
        self.steamid = str(steamid)
        self.version = version
        self.token = token
        self.key = secrets.token_hex(16).upper().encode()   # 32 ASCII hex
        self.iv = secrets.token_hex(8).upper().encode()     # 16 ASCII hex

    # -- handshake ---------------------------------------------------------
    def login(self):
        payload = json.dumps({
            'steamid': self.steamid, 'appid': APPID, 'version': self.version,
            'key': self.key.decode(), 'iv': self.iv.decode(),
        }, separators=(',', ':')).encode()
        block = _rsa.load_private().public_key().encrypt(payload, padding.PKCS1v15())
        enc = base64.b64encode(block).decode()
        raw = _post(API_HOST, '/api/c2s_login', {
            'data': enc, 'ticket': secrets.token_hex(20), 'identity': self.steamid},
            token=self.token)
        # Login responses use the API cipher, not the magic framing.
        try:
            return json.loads(_aes_dec(base64.b64decode(raw), self.key, self.iv))
        except Exception:
            return {'_raw': raw[:120].decode('utf-8', 'replace')}

    # -- api ---------------------------------------------------------------
    def call(self, endpoint: str, obj: dict):
        pt = json.dumps(obj, separators=(',', ':')).encode()
        data = base64.b64encode(MAGIC + _aes_enc(pt, self.key, self.iv)).decode()
        raw = _post(API_HOST, f'/api/{endpoint}', {'data': data}, token=self.token)
        return json.loads(_aes_dec(base64.b64decode(raw), self.key, self.iv))

    def myinfo(self):
        return self.call('c2s_get_myinfo', {'appid': APPID})

    def play(self, musicid, keymode, levelmode, score, kool=0, cool=0,
             good=0, miss=0, fail=0, lamp=2, rate=0.0, combo=0):
        return self.call('c2s_set_game_clear', {
            'musicid': musicid, 'keymode': keymode, 'levelmode': levelmode,
            'lamp': lamp, 'score': score, 'rate': rate, 'combo': combo,
            'kool': kool, 'cool': cool, 'good': good, 'miss': miss, 'fail': fail})

    def userinfo(self, steamids):
        return self.call('c2s_get_userinfo', {
            'appid': APPID, 'steamId': [int(s) for s in steamids]})

    def leaderboard(self, musicid, keymode, levelmode, page=0, steamid=None):
        key = f'{musicid}{keymode}{levelmode}'
        q = f'get{key},{page}' + (f',{steamid}' if steamid else '')
        return _get(RANK_HOST, '/?' + urllib.parse.urlencode({'data': q}),
                    token=self.token).decode()


def _cleared(info):
    cl = info.get('clearlist') or []
    # a non-zero SCORE slot anywhere in a clearlist entry = a played variant
    played = 0
    for e in cl:
        for k in ('SCORE', 'LAMP', 'PLAY_COUNT'):
            v = str(e.get(k, '0'))
            if v.replace(',', '').strip('0.') != '':
                played += sum(1 for x in v.split(',') if x not in ('', '0', '0.00'))
                break
    return len(cl), played


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('steamid')
    ap.add_argument('--musicid', type=int, default=95111)  # Conflict
    ap.add_argument('--keymode', type=int, default=1)       # 4K
    ap.add_argument('--levelmode', type=int, default=1)     # EZ
    ap.add_argument('--score', type=int, default=0)
    ap.add_argument('--token', default=os.environ.get('EZ2_TOKEN'),
                    help='server account token (or $EZ2_TOKEN); omitted = guest/open')
    ap.add_argument('--remote', default=None,
                    help='standalone server base URL (default $PSERVER_REMOTE); '
                         'when set, talk to it directly instead of a local proxy')
    ap.add_argument('--insecure', action='store_true',
                    help='skip TLS verification of --remote')
    ap.add_argument('--play', action='store_true', help='record a clear')
    ap.add_argument('--leaderboard', action='store_true')
    args = ap.parse_args()

    global REMOTE, INSECURE
    if args.remote:
        REMOTE = args.remote.rstrip('/')
    if args.insecure:
        INSECURE = True

    c = FakeClient(args.steamid, token=args.token)
    print(f'login {args.steamid}: {c.login()}')
    info = c.myinfo()
    mi = info.get('memberinfo', {})
    if isinstance(mi, list):
        mi = mi[0] if mi else {}
    print(f'myinfo: LEVEL={mi.get("LEVEL")} RATING={mi.get("RATING")} '
          f'clearlist={len(info.get("clearlist") or [])} entries')
    if args.play:
        print('play ->', c.play(args.musicid, args.keymode, args.levelmode,
                                args.score))
        info = c.myinfo()
        mi = info.get('memberinfo', {})
        if isinstance(mi, list):
            mi = mi[0] if mi else {}
        print(f'myinfo after play: LEVEL={mi.get("LEVEL")} '
              f'clearlist={len(info.get("clearlist") or [])} entries')
    print('userinfo ->', c.userinfo([args.steamid]))
    if args.leaderboard or args.play:
        csv = c.leaderboard(args.musicid, args.keymode, args.levelmode)
        triplets = [csv.split(',')[i:i + 3] for i in range(0, len(csv.split(',')), 3)]
        hit = [t for t in triplets if t and t[-1] == args.steamid]
        print(f'leaderboard {args.musicid}/{args.keymode}/{args.levelmode}: '
              f'{len([t for t in triplets if t])} rows; me={hit}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
