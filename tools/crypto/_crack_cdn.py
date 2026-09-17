#!/usr/bin/env python3
"""Broad cracker for the CDN .ezi/.ez ciphertext."""
import base64, glob, os, gzip, zlib, lzma, bz2
from Crypto.Cipher import AES

BCK = "BgpE/G7d3K5q/q831Rp0Zat6X7EepFML+RA13+CDHYoJorvN1YAxfb/Ousio2djw"
BCK_RAW = base64.b64decode(BCK + '=' * (-len(BCK) % 4))
ZF_KEY = b'C7E3C35D846086B6610CF7DEE4F0A192'   # ascii, 32 bytes
ZF_IV  = b'BAE5707397612215'                  # ascii, 16 bytes

def hx(s): return bytes.fromhex(s)
SV = {
    'svk': hx('b6267ea195763df32ec91ed39d7f66035ca002de4dee12fff9cf93ed92163e0d'),
    'svl': hx('8c8e78a8cae9885cc5438b58e2931609'),
    'svm': hx('1c041e8ebb58fdb485deb781fa756696a45ff1bf1ba7d9e85663a01c62bb1f2b'),
    'svn': hx('8e763cd2a4d409d62658d626c06f027c'),
    'svo': hx('7dbb2047f7def50c7c30a7709f6b4bac1dc3aebee52f455fe801a32b29518b1d'),
    'svp': hx('0d1a6bcb9c80f1b53bdaf766ed40012f'),
    'svr': hx('d0d9223422c56c6ce10496cc0a44777d'),
    'zf_key': ZF_KEY, 'zf_iv': ZF_IV,
    'bck_raw': BCK_RAW, 'bck_ascii': BCK.encode(),
}

KEYS = []
def addk(name, k):
    if len(k) in (16, 24, 32): KEYS.append((name, k))
addk('zf_key', ZF_KEY)
addk('bck[0:32]', BCK_RAW[:32])
addk('bck[16:48]', BCK_RAW[16:48])
addk('bck_ascii[0:32]', BCK.encode()[:32])
addk('bck_ascii[0:16]', BCK.encode()[:16])
for n, v in SV.items():
    addk(n, v[:32]); addk(n, v[:16])

IVS = [('zf_iv', ZF_IV), ('bck[32:48]', BCK_RAW[32:48]), ('bck[0:16]', BCK_RAW[0:16]),
       ('bck[16:32]', BCK_RAW[16:32]), ('bck_ascii[32:48]', BCK.encode()[32:48]),
       ('zero', b'\x00'*16)]

def looks(b):
    if not b: return None
    if b[:4] == b'EZFF': return 'EZFF!'
    pr = sum(1 for c in b[:400] if 9 <= c < 127) / min(400, len(b))
    if pr > 0.9: return f'ASCII: {b[:70]!r}'
    for mn, fn in [('zlib', zlib.decompress), ('gzip', gzip.decompress), ('raw', lambda x: zlib.decompress(x, -15)), ('lzma', lzma.decompress), ('bz2', bz2.decompress)]:
        try:
            o = fn(b); 
            if len(o) > 32: return f'{mn} -> {len(o)}B {o[:40]!r}'
        except Exception: pass
    return None

def crack(data, label):
    for kn, k in KEYS:
        for ivn, iv in IVS:
            try:
                c = AES.new(k, AES.MODE_CBC, iv=iv); out = c.decrypt(data[:len(data)//16*16])
                r = looks(out)
                if r: print(f"  [HIT] {label} key={kn} iv={ivn} CBC: {r}")
            except Exception: pass
            try:
                c = AES.new(k, AES.MODE_CFB, iv=iv); out = c.decrypt(data)
                r = looks(out)
                if r: print(f"  [HIT] {label} key={kn} iv={ivn} CFB: {r}")
            except Exception: pass
            try:
                c = AES.new(k, AES.MODE_OFB, iv=iv); out = c.decrypt(data)
                r = looks(out)
                if r: print(f"  [HIT] {label} key={kn} iv={ivn} OFB: {r}")
            except Exception: pass
            for order in ('big', 'little'):
                try:
                    c = AES.new(k, AES.MODE_CTR, nonce=b'', initial_value=int.from_bytes(iv, order)); out = c.decrypt(data)
                    r = looks(out)
                    if r: print(f"  [HIT] {label} key={kn} iv={ivn} CTR-{order}: {r}")
                except Exception: pass
        try:
            c = AES.new(k, AES.MODE_ECB); out = c.decrypt(data[:len(data)//16*16])
            r = looks(out)
            if r: print(f"  [HIT] {label} key={kn} ECB: {r}")
        except Exception: pass
    # raw compression attempt
    for mn, fn in [('zlib', zlib.decompress), ('gzip', gzip.decompress), ('raw', lambda x: zlib.decompress(x, -15)), ('lzma', lzma.decompress), ('bz2', bz2.decompress)]:
        try:
            o = fn(data)
            if len(o) > 32: print(f"  [HIT] {label} plain-{mn}: {len(o)}B {o[:40]!r}")
        except Exception: pass

data = open(glob.glob('mitm_parsed/cdn_018_*.bin')[0], 'rb').read()
print(f"testing Engine .ezi: {len(data)} bytes, first: {data[:32].hex()}")
crack(data, 'Engine-ezi')
print("done")
