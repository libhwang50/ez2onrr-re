#!/usr/bin/env python3
"""Decrypt all c2s_get_pattern_file responses with the session key -> extract bundleCryptKey."""
import json, base64, glob, os, re
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Session keys rotate per launch and are never committed; supply the session
# that produced your captures:
#   EZ2_API_SESSION_KEY / EZ2_API_SESSION_IV   (ASCII zf.aes_key / zf.aes_iv)
#   EZ2_BUNDLE_CRYPT_KEY                       (base64 bundleCryptKey)
KEY = os.environ.get('EZ2_API_SESSION_KEY', '').encode()
IV  = os.environ.get('EZ2_API_SESSION_IV', '').encode()

def dec_cbc(ct):
    c = AES.new(KEY, AES.MODE_CBC, iv=IV)
    return unpad(c.decrypt(ct), 16)

def b64d(s):
    s = s.strip()
    return base64.b64decode(s + '=' * (-len(s) % 4))

out = []
for f in sorted(glob.glob('mitm_parsed/pattern_*.json')):
    d = json.load(open(f))
    body = d.get('resp_body_text') or ''
    if not body:
        continue
    try:
        pt = dec_cbc(b64d(body))
        js = json.loads(pt.decode('utf-8'))
    except Exception as e:
        print(f"[{f}] FAIL: {e}")
        continue
    rec = {'file': f, 'json': js}
    out.append(rec)
    print(f"=== {f} ===")
    print(json.dumps(js, indent=1)[:1200])
    print()

with open('mitm_parsed/pattern_keys.json', 'w') as f:
    json.dump(out, f, indent=1)
print(f"decrypted {len(out)} responses -> mitm_parsed/pattern_keys.json")
