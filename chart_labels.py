#!/usr/bin/env python3
"""Build a chart labels file (song name, key mode, difficulty) from captured API traffic.

The game asks for each chart with `c2s_get_pattern_file`, whose request body carries
`musicresourcename`, `keymode`, `levelmode` and `gamemode` — and whose response carries the
signed CDN URLs. So a mitm capture gives us the labels for any chart we also captured.

`dump_song.py` reads the resulting JSON and matches its current `ezi_url` against it, which
is how a capture gets a readable name instead of `song_<hash>`.

Usage
-----
    python3 label_charts.py                       # writes chart_labels.json
    python3 label_charts.py --mitm mitm_parsed -o chart_labels.json
    python3 label_charts.py --key <EZ2_API_SESSION_KEY> --iv <EZ2_API_SESSION_IV>

Note the session key/IV: they are static fields on `zf`, overwritten at login, so captures
from a different session need that session's values. Harvest them live with
`tools/il2cpp/_statics.js` (`zf.aes_key` / `zf.aes_iv`).
"""
import argparse
import base64
import glob
import json
import os
import sys
import urllib.parse

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Session keys rotate per launch and are never committed; supply the session
# that produced your captures:
#   EZ2_API_SESSION_KEY / EZ2_API_SESSION_IV   (ASCII zf.aes_key / zf.aes_iv)
#   EZ2_BUNDLE_CRYPT_KEY                       (base64 bundleCryptKey)
DEFAULT_KEY = os.environ.get('EZ2_API_SESSION_KEY', '')
DEFAULT_IV = os.environ.get('EZ2_API_SESSION_IV', '')

# Request bodies carry a 6-byte header before the AES-CBC ciphertext.
REQ_HEADER = 6


def decrypt(blob, key, iv):
    return unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(blob), 16)


def b64(s):
    s = s.strip()
    return base64.b64decode(s + '=' * (-len(s) % 4))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--mitm', default='mitm_parsed', help='dir with pattern_*.json captures')
    ap.add_argument('--key', default=DEFAULT_KEY, help='session AES key (ASCII)')
    ap.add_argument('--iv', default=DEFAULT_IV, help='session AES IV (ASCII)')
    ap.add_argument('-o', '--out', default='chart_labels.json')
    args = ap.parse_args()

    key = args.key.encode() if isinstance(args.key, str) else args.key
    iv = args.iv.encode() if isinstance(args.iv, str) else args.iv
    if len(key) != 32 or len(iv) != 16:
        sys.exit('key must be 32 chars and iv 16 chars (got %d/%d)' % (len(key), len(iv)))

    out = {}
    files = sorted(glob.glob(os.path.join(args.mitm, 'pattern_*.json')))
    if not files:
        sys.exit('no pattern_*.json under %s' % args.mitm)
    for path in files:
        d = json.load(open(path))
        if not isinstance(d, dict):
            continue
        try:
            req = json.loads(decrypt(b64(urllib.parse.unquote(d['req_body_text'][5:] + '==='))
                                     [REQ_HEADER:], key, iv))
            resp = json.loads(decrypt(b64(d['resp_body_text']), key, iv))
        except Exception as e:
            print('  %-24s SKIP: %s' % (os.path.basename(path), e))
            continue
        rec = {'song': req.get('musicresourcename'), 'keymode': req.get('keymode'),
               'levelmode': req.get('levelmode'), 'gamemode': req.get('gamemode'),
               'source': os.path.basename(path)}
        # index by the stable path segment of each URL, so dump_song can match on it
        for kind in ('ez', 'ezi'):
            url = (resp.get('final_url_' + kind) or '').split('?')[0]
            if url:
                out[url.split('/')[-1].split('.')[0][:24]] = rec
        print('  %-24s %-14s keymode=%s levelmode=%s gamemode=%s'
              % (os.path.basename(path), rec['song'], rec['keymode'], rec['levelmode'],
                 rec['gamemode']))

    json.dump(out, open(args.out, 'w'), indent=1)
    print('\n%d URL(s) labelled -> %s' % (len(out), args.out))


if __name__ == '__main__':
    main()
