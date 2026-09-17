#!/usr/bin/env python3
"""Broad CDN cracker: key variants (direct/hashed) x IV variants x modes."""
import base64, glob, hashlib, zlib
from Crypto.Cipher import AES

BCK = "BgpE/G7d3K5q/q831Rp0Zat6X7EepFML+RA13+CDHYoJorvN1YAxfb/Ousio2djw"
BCK_RAW = base64.b64decode(BCK + '=' * (-len(BCK) % 4))
ZF_KEY = b'C7E3C35D846086B6610CF7DEE4F0A192'
ZF_IV = b'BAE5707397612215'
FIXED = bytes.fromhex('d3ad76d3adb846d599fae4c451509c06')

def hx(s): return bytes.fromhex(s)
SV = {
    'svk': hx('b6267ea195763df32ec91ed39d7f66035ca002de4dee12fff9cf93ed92163e0d'),
    'svl': hx('8c8e78a8cae9885cc5438b58e2931609'),
    'svm': hx('1c041e8ebb58fdb485deb781fa756696a45ff1bf1ba7d9e85663a01c62bb1f2b'),
    'svn': hx('8e763cd2a4d409d62658d626c06f027c'),
    'svo': hx('7dbb2047f7def50c7c30a7709f6b4bac1dc3aebee52f455fe801a32b29518b1d'),
    'svp': hx('0d1a6bcb9c80f1b53bdaf766ed40012f'),
    'svr': hx('d0d9223422c56c6ce10496cc0a44777d'),
}

# Build key candidates
KEYS = {}
def add(name, k):
    if len(k) in (16, 24, 32) and name not in KEYS: KEYS[name] = k

def windows(name, blob):
    for L in (16, 24, 32):
        if len(blob) >= L:
            add(f'{name}[0:{L}]', blob[:L])
            add(f'{name}[-{L}:]', blob[-L:])
        add(f'{name}[16:{16+L}]', blob[16:16+L])

mat = {'bck_raw': BCK_RAW, 'bck_ascii': BCK.encode(), 'zf_key': ZF_KEY}
for n, b in mat.items():
    windows(n, b)
    for h in ('md5', 'sha1', 'sha256', 'sha512'):
        d = hashlib.new(h, b).digest()
        windows(f'{h}({n})', d)
for n, b in SV.items():
    windows(n, b)
add('zf_iv', ZF_IV)
windows('zf_iv', ZF_IV)

# IV candidates
IVS = {}
def addiv(name, iv):
    if len(iv) == 16 and name not in IVS: IVS[name] = iv
addiv('fixed', FIXED); addiv('zf_iv', ZF_IV); addiv('zero', b'\x00'*16)
for n, b in [('bck_raw', BCK_RAW), ('bck_ascii', BCK.encode())]:
    for i in range(0, max(1, len(b)-15)):
        addiv(f'{n}[{i}:{i+16}]', b[i:i+16])
for n, b in SV.items():
    if len(b) >= 16: addiv(n, b[:16])
# hashed IVs
for h in ('md5', 'sha1', 'sha256'):
    addiv(f'{h}(bck)', hashlib.new(h, BCK_RAW).digest()[:16])
    addiv(f'{h}(bck_ascii)', hashlib.new(h, BCK.encode()).digest()[:16])

def looks(b):
    if not b: return None
    if b[:4] == b'EZFF': return 'EZFF!'
    pr = sum(1 for c in b[:400] if 9 <= c < 127) / min(400, len(b))
    if pr > 0.9: return f'ASCII: {b[:70]!r}'
    for mn, fn in [('zlib', zlib.decompress), ('gzip', __import__('gzip').decompress), ('raw', lambda x: zlib.decompress(x, -15))]:
        try:
            o = fn(b)
            if len(o) > 32: return f'{mn}->{len(o)}B {o[:40]!r}'
        except Exception: pass
    return None

data = open(glob.glob('mitm_parsed/cdn_018_*.bin')[0], 'rb').read()
print(f"target: {len(data)} B, {data[:16].hex()}")
found = 0
for kn, k in KEYS.items():
    for ivn, iv in IVS.items():
        for mode, mn in [(AES.MODE_CBC, 'CBC'), (AES.MODE_CFB, 'CFB'), (AES.MODE_OFB, 'OFB')]:
            try:
                c = AES.new(k, mode, iv=iv)
                out = c.decrypt(data[:len(data)//16*16] if mode == AES.MODE_CBC else data)
                r = looks(out)
                if r:
                    print(f"[HIT] key={kn} iv={ivn} {mn}: {r}"); found += 1
            except Exception: pass
        try:
            c = AES.new(k, AES.MODE_CTR, nonce=b'', initial_value=int.from_bytes(iv, 'big'))
            r = looks(c.decrypt(data))
            if r: print(f"[HIT] key={kn} iv={ivn} CTR-BE: {r}"); found += 1
        except Exception: pass
    try:
        c = AES.new(k, AES.MODE_ECB)
        r = looks(c.decrypt(data[:len(data)//16*16]))
        if r: print(f"[HIT] key={kn} ECB: {r}"); found += 1
    except Exception: pass
print(f"done, {found} hits (tried {len(KEYS)} keys x {len(IVS)} ivs)")
