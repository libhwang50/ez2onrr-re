#!/usr/bin/env python3
"""Exhaustive key/iv window search over bundleCryptKey for the CDN cipher."""
import base64, glob
import os
from Crypto.Cipher import AES

BCK = os.environ.get('EZ2_BUNDLE_CRYPT_KEY', '')
RAW = base64.b64decode(BCK + '=' * (-len(BCK) % 4))
ASC = BCK.encode()
ZF_KEY = os.environ.get('EZ2_API_SESSION_KEY', '').encode()
ZF_IV = os.environ.get('EZ2_API_SESSION_IV', '').encode()

def windows(blob, lens=(16, 24, 32)):
    out = []
    for L in lens:
        for s in range(0, len(blob) - L + 1):
            out.append((s, L, (blob[s:s+L] if len(blob) >= L else None)))
    return out

key_cands = []
for tag, blob in [('raw', RAW), ('asc', ASC)]:
    for L in (16, 24, 32):
        for s in range(0, len(blob) - L + 1):
            key_cands.append((f'{tag}[{s}:{s+L}]', blob[s:s+L]))
key_cands += [('zf_key', ZF_KEY), ('zf_iv_pad', ZF_IV + b'\x00'*16)]
# dedupe
seen = set(); kc = []
for n, k in key_cands:
    if k not in seen:
        seen.add(k); kc.append((n, k))
key_cands = kc

iv_cands = []
for tag, blob in [('raw', RAW), ('asc', ASC)]:
    for s in range(0, len(blob) - 16 + 1):
        iv_cands.append((f'{tag}[{s}:{s+16}]', blob[s:s+16]))
iv_cands += [('zf_iv', ZF_IV), ('zero', b'\x00'*16)]
seen = set(); ic = []
for n, iv in iv_cands:
    if iv not in seen:
        seen.add(iv); ic.append((n, iv))
iv_cands = ic

def is_ezff(b):
    return b[:4] == b'EZFF'
def is_ez(b):
    # plaintext keysound map: starts with digits, then space
    if not b: return False
    j = 0
    while j < len(b) and 48 <= b[j] <= 57: j += 1
    return j > 0 and j < 6 and j < len(b) and b[j:j+1] == b' '

data = open(glob.glob('mitm_parsed/cdn_018_*.bin')[0], 'rb').read()
d16 = data[:len(data)//16*16]
print(f"target {len(data)} B, {len(key_cands)} keys x {len(iv_cands)} ivs")

hits = 0
for kn, k in key_cands:
    for ivn, iv in iv_cands:
        for mode, mn in [(AES.MODE_CBC, 'CBC'), (AES.MODE_CFB, 'CFB'), (AES.MODE_OFB, 'OFB')]:
            try:
                c = AES.new(k, mode, iv=iv)
                out = c.decrypt(d16 if mode == AES.MODE_CBC else data)
                if is_ezff(out) or is_ez(out):
                    print(f"[HIT!] key={kn} iv={ivn} {mn}: {out[:60]!r}"); hits += 1
            except Exception: pass
        try:
            c = AES.new(k, AES.MODE_CTR, nonce=b'', initial_value=int.from_bytes(iv, 'big'))
            out = c.decrypt(data)
            if is_ezff(out) or is_ez(out):
                print(f"[HIT!] key={kn} iv={ivn} CTR: {out[:60]!r}"); hits += 1
        except Exception: pass
    try:
        c = AES.new(k, AES.MODE_ECB)
        out = c.decrypt(d16)
        if is_ezff(out) or is_ez(out):
            print(f"[HIT!] key={kn} ECB: {out[:60]!r}"); hits += 1
    except Exception: pass
print(f"done, {hits} hits")
