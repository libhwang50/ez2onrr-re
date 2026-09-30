#!/usr/bin/env python3
"""ripper/collect_read.py — read and decrypt a bundle from `ripper/collect.py`.

A tester submits the zip (or directory) that `ripper/collect.py` produced; this
turns it back into readable API traffic.  Each flow already carries the session
key that was live when it was recorded, so no extra input is needed.

    python3 ripper/collect_read.py collected/20261001-120000.zip
    python3 ripper/collect_read.py collected/20261001-120000 --path login
    python3 ripper/collect_read.py collected/20261001-120000 --dump /tmp/out
    python3 ripper/collect_read.py collected/20261001-120000 --list

The API body formats (from the capture notes):
  * request  = form field `data=` -> b64 -> magic `d3ad76d3adb8` (6 B) || AES-CBC
  * response = b64 -> AES-CBC/PKCS7
  * key/IV   = the ASCII bytes of the client's live `zf.aes_key` (32) / `zf.aes_iv` (16)
A login *request* is additionally RSA-wrapped, so it will not decrypt here; the
login *response* will.
"""
import argparse
import base64
import json
import os
import sys
import urllib.parse
import zipfile

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

MAGIC = bytes.fromhex('d3ad76d3adb8')


def _aes(key, iv, ct):
    return unpad(AES.new(key.encode(), AES.MODE_CBC, iv=iv.encode()).decrypt(ct), 16)


def dec_response(body_b64, key):
    """Official response body -> json object (or None)."""
    if not body_b64 or not key:
        return None
    try:
        raw = base64.b64decode(body_b64 + '=' * (-len(body_b64) % 4))
        return json.loads(_aes(key['aes_key'], key['aes_iv'], raw).decode('utf-8'))
    except Exception:
        return None


def dec_request(body_b64, key):
    """Official request body -> json object (or None; login is RSA-wrapped)."""
    if not body_b64 or not key:
        return None
    try:
        form = base64.b64decode(body_b64 + '=' * (-len(body_b64) % 4)).decode(
            'utf-8', 'replace')
        val = None
        for part in form.split('&'):
            k, _, v = part.partition('=')
            if k == 'data':
                val = urllib.parse.unquote(v)
                break
        if val is None:
            return None
        raw = base64.b64decode(val + '=' * (-len(val) % 4))
        if raw[:6] != MAGIC:
            return None
        return json.loads(_aes(key['aes_key'], key['aes_iv'], raw[6:]).decode('utf-8'))
    except Exception:
        return None


def _read(bundle, name):
    if os.path.isdir(bundle):
        p = os.path.join(bundle, name)
        return open(p, 'rb').read() if os.path.exists(p) else None
    with zipfile.ZipFile(bundle) as z:
        try:
            return z.read(name)
        except KeyError:
            return None


def load(bundle):
    flows = []
    raw = _read(bundle, 'flows.jsonl')
    if raw:
        for line in raw.decode('utf-8', 'replace').splitlines():
            line = line.strip()
            if line:
                try:
                    flows.append(json.loads(line))
                except Exception:
                    pass
    meta = {}
    mraw = _read(bundle, 'meta.json')
    if mraw:
        try:
            meta = json.loads(mraw)
        except Exception:
            pass
    return flows, meta


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('bundle', help='a collect.py bundle directory or .zip')
    ap.add_argument('--path', help='only flows whose path contains this substring')
    ap.add_argument('--host', help='only flows whose host contains this substring')
    ap.add_argument('--list', action='store_true', help='list only, do not decrypt')
    ap.add_argument('--no-decrypt', action='store_true', help='same as --list')
    ap.add_argument('--dump', metavar='DIR',
                    help='write each decrypted body as DIR/<n>_<endpoint>.json')
    ap.add_argument('--full', action='store_true',
                    help='print full JSON instead of a truncated summary')
    args = ap.parse_args()

    flows, meta = load(args.bundle)
    if not flows:
        sys.exit('[collect_read] no flows found in %s' % args.bundle)
    if meta:
        print('[collect_read] bundle: %s flows, tool=%s, host=%s, patcher=%s'
              % (meta.get('flows', len(flows)), meta.get('tool'), meta.get('host'),
                 meta.get('patcher')))
    if args.dump:
        os.makedirs(args.dump, exist_ok=True)

    listed = 0
    for i, r in enumerate(flows):
        path = r.get('path') or ''
        host = r.get('host') or ''
        if args.path and args.path not in path:
            continue
        if args.host and args.host not in host:
            continue
        listed += 1
        ep = path.split('?')[0].rstrip('/').split('/')[-1] or host
        key = r.get('key')
        print('\n=== #%d %s %s%s  status=%s  resp=%sB  key=%s ==='
              % (i, r.get('method'), host, path.split('?')[0],
                 r.get('status'), r.get('resp_len'),
                 (key or {}).get('aes_key') or '(none)'))
        if args.list or args.no_decrypt:
            continue
        req = dec_request(r.get('req_body_b64'), key)
        resp = dec_response(r.get('resp_body_b64'), key)
        if req is not None:
            print('  request :', json.dumps(req, ensure_ascii=False))
        if resp is not None:
            print('  response:', json.dumps(resp, ensure_ascii=False)
                  if args.full else json.dumps(resp, ensure_ascii=False)[:2000])
        if req is None and resp is None:
            print('  (nothing decrypted — RSA-wrapped login request, or key missing)')
        if args.dump:
            for kind, obj in (('req', req), ('resp', resp)):
                if obj is None:
                    continue
                fn = os.path.join(args.dump, '%03d_%s_%s.json' % (i, ep, kind))
                with open(fn, 'w') as f:
                    json.dump(obj, f, indent=1, ensure_ascii=False)
    print('\n[collect_read] %d/%d flow(s) shown' % (listed, len(flows)))


if __name__ == '__main__':
    main()
