#!/usr/bin/env python3
"""Test prepended-IV hypotheses + XOR variants for the CDN cipher."""
import base64, glob
from Crypto.Cipher import AES

BCK = "BgpE/G7d3K5q/q831Rp0Zat6X7EepFML+RA13+CDHYoJorvN1YAxfb/Ousio2djw"
RAW = base64.b64decode(BCK + '=' * (-len(BCK) % 4))
ASC = BCK.encode()
ZF_KEY = b'C7E3C35D846086B6610CF7DEE4F0A192'
ZF_IV = b'BAE5707397612215'

KEYS = [('zf_key', ZF_KEY), ('bck[0:32]', RAW[:32]), ('bck[16:48]', RAW[16:48]),
        ('bck_asc[0:32]', ASC[:32]), ('bck_asc[32:64]', ASC[32:]),
        ('bck[32:48]pad', RAW[32:48] + b'\x00'*16)]
# add 16-byte keys too
KEYS += [('bck[0:16]', RAW[:16]), ('bck_asc[0:16]', ASC[:16])]

def ezff(b): return b[:4] == b'EZFF'
def ez_ok(b):
    if len(b) < 40: return False
    pr = sum(1 for c in b[:200] if 9 <= c < 127) / 200
    # look for at least one space-separated triple
    s = b[:200].decode('latin-1', 'ignore')
    return pr > 0.95 and s.count(' ') >= 3 and any(ch.isdigit() for ch in s[:10])

def report(tag, out):
    if ezff(out): print(f"  [EZFF!!] {tag}: {out[:80]!r}")
    elif ez_ok(out): print(f"  [EZ?] {tag}: {out[:80]!r}")

for path in sorted(glob.glob('mitm_parsed/cdn_018_*.bin')) + sorted(glob.glob('mitm_parsed/cdn_019_*.bin')):
    data = open(path, 'rb').read()
    print(f"\n=== {path.split('/')[-1]} ({len(data)} B) ===")
    for kn, k in KEYS:
        if len(k) not in (16, 24, 32): continue
        # prepended IV hypothesis: iv = data[0:16], ct = data[16:]
        iv = data[:16]; ct = data[16:]
        for mode, mn in [(AES.MODE_CBC, 'CBC'), (AES.MODE_CFB, 'CFB'), (AES.MODE_OFB, 'OFB')]:
            try:
                c = AES.new(k, mode, iv=iv)
                out = c.decrypt(ct[:len(ct)//16*16] if mode == AES.MODE_CBC else ct)
                report(f'{kn} {mn} prep-IV', out)
            except Exception: pass
        try:
            c = AES.new(k, AES.MODE_CTR, nonce=b'', initial_value=int.from_bytes(iv, 'big'))
            report(f'{kn} CTR prep-IV', c.decrypt(ct))
        except Exception: pass
        # fixed session IV
        for mode, mn in [(AES.MODE_CBC, 'CBC'), (AES.MODE_CFB, 'CFB'), (AES.MODE_OFB, 'OFB')]:
            try:
                c = AES.new(k, mode, iv=ZF_IV)
                out = c.decrypt(data[:len(data)//16*16] if mode == AES.MODE_CBC else data)
                report(f'{kn} {mn} zf-IV', out)
            except Exception: pass
    # XOR variants
    for name, stream in [('bck_raw', RAW), ('bck_asc', ASC), ('zf_key', ZF_KEY), ('zf_iv', ZF_IV)]:
        ks = (stream * (len(data)//len(stream) + 1))[:len(data)]
        out = bytes(a ^ b for a, b in zip(data, ks))
        report(f'XOR-{name}', out)
print("\ndone")
