#!/usr/bin/env python3
"""Decrypt the captured CDN .ezi/.ez ciphertext with bundleCryptKey."""
import json, base64, glob, os, re
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

BCK = "BgpE/G7d3K5q/q831Rp0Zat6X7EepFML+RA13+CDHYoJorvN1YAxfb/Ousio2djw"
bck_raw = base64.b64decode(BCK + '=' * (-len(BCK) % 4))
print(f"bundleCryptKey: {len(BCK)} chars -> {len(bck_raw)} bytes")
print(f"  hex: {bck_raw.hex()}")

# map url-hash -> cdn file
cdn_files = {}
for p in glob.glob('mitm_parsed/cdn_*.bin'):
    # name: cdn_NNN_<safe_path>.bin ; the path starts with fb_2_...
    m = re.search(r"cdn_\d+_(.+)\.bin", os.path.basename(p))
    if m:
        cdn_files[m.group(1)] = p

def find_cdn(url):
    # extract /fb_2/xx/hash -> fb_2_xx_hash
    mm = re.search(r'/fb_2/([0-9a-f]+)/([0-9a-f]+)\?', url)
    if not mm: return None
    key = f"fb_2_{mm.group(1)}_{mm.group(2)}"
    return cdn_files.get(key)

def looks(b):
    if not b: return None
    if b[:4] == b'EZFF': return 'EZFF!'
    pr = sum(1 for c in b[:400] if 9 <= c < 127) / min(400, len(b))
    if pr > 0.9: return f'ASCII {pr:.2f}: {b[:80]!r}'
    return None

def try_dec(data, label):
    k32 = bck_raw[:32]; iv16 = bck_raw[32:48]
    candidates = [
        ('b64[0:32]/[32:48]', k32, iv16),
        ('b64[16:48]/[0:16]', bck_raw[16:48], bck_raw[0:16]),
        ('b64[0:16]/[16:32]', bck_raw[0:16], bck_raw[16:32]),
        ('ascii[0:32]/[32:48]', BCK.encode()[:32], BCK.encode()[32:48]),
        ('ascii[0:16]/[16:32]', BCK.encode()[:16], BCK.encode()[16:32]),
    ]
    for name, k, iv in candidates:
        if len(k) not in (16, 24, 32) or len(iv) != 16: continue
        for mode, mn in [(AES.MODE_CBC, 'CBC'), (AES.MODE_CFB, 'CFB'), (AES.MODE_OFB, 'OFB')]:
            try:
                c = AES.new(k, mode, iv=iv)
                out = c.decrypt(data[:len(data)//16*16] if mode == AES.MODE_CBC else data)
                r = looks(out)
                if r: print(f"  [HIT] {label} {name} {mn}: {r}")
            except Exception: pass
        try:
            c = AES.new(k, AES.MODE_ECB)
            out = c.decrypt(data[:len(data)//16*16])
            r = looks(out)
            if r: print(f"  [HIT] {label} {name} ECB: {r}")
        except Exception: pass

keys = json.load(open('mitm_parsed/pattern_keys.json'))
for rec in keys:
    js = rec['json']
    for fld, ext in (('final_url_ezi', 'ezi'), ('final_url_ez', 'ez')):
        url = js.get(fld)
        p = find_cdn(url) if url else None
        if not p:
            continue
        data = open(p, 'rb').read()
        print(f"\n--- pattern {rec['file']} {fld} -> {os.path.basename(p)} ({len(data)} B) ---")
        try_dec(data, os.path.basename(p))
