#!/usr/bin/env python3
"""Try decrypting captured .ezi/.ez ciphertext with harvested key material."""
import sys
import zlib, gzip, lzma
from Crypto.Cipher import AES

files = {
    'ez':  open('extracted_charts/5dae1cc7be12209ba540c0234b64ff8d1e672e540ab0bcfc09c8a0941bcb6e.ez', 'rb').read(),
    'ezi': open('extracted_charts/4f3a20b5d9c489b435a74e985db2d1c299a0b51ecb896280e6cc43c18b5b0a.ezi', 'rb').read(),
}

def hx(s): return bytes.fromhex(s)

# key material harvested live from InGameCore statics (this session) + prior candidates
KEYS = {
    'svk(32)': hx('b6267ea195763df32ec91ed39d7f66035ca002de4dee12fff9cf93ed92163e0d'),
    'svl(16)': hx('8c8e78a8cae9885cc5438b58e2931609'),
    'svm(32)': hx('1c041e8ebb58fdb485deb781fa756696a45ff1bf1ba7d9e85663a01c62bb1f2b'),
    'svn(16)': hx('8e763cd2a4d409d62658d626c06f027c'),
    'svo(32)': hx('7dbb2047f7def50c7c30a7709f6b4bac1dc3aebee52f455fe801a32b29518b1d'),
    'svp(16)': hx('0d1a6bcb9c80f1b53bdaf766ed40012f'),
    'svq(64)': hx('31a3e172df7b44db465c84ad28f5a5a59875772fab5a062a8c2e44cfe8a5ba441e68ecdb8ccdfcce716c5268f09754904192c9912759d1780a7a7705737fc6ca'),
    'svr(16)': hx('d0d9223422c56c6ce10496cc0a44777d'),
    # prior session candidates
    'zf.aes_key(16)': hx('4A6469F1358147858EFD430E44FD8A57'),
    'zf.aes_iv(8)': hx('F8BECB8836AFA814'),
    'da.aes_key(32)': b'91534567190123456709012745679903',
    'da.aes_iv(16)': b'0173456089512849',
    'qe.aes_key(32)': b'31274527810126456489012345678909',
    'qe.aes_iv(16)': b'9824450789003347',
}

IVS = ['svl(16)', 'svn(16)', 'svp(16)', 'svr(16)']

def looks_good(b, fn):
    if not b: return None
    if fn == 'ezi' and b[:4] == b'EZFF':
        return 'EZFF!'
    if fn == 'ez':
        pr = sum(1 for c in b[:400] if 9 <= c < 127) / min(400, len(b))
        if pr > 0.9:
            return f'ASCII {pr:.2f} first={b[:60]!r}'
    for m, f in [('gzip', gzip.decompress), ('zlib', zlib.decompress),
                 ('deflate', lambda x: zlib.decompress(x, -15)), ('lzma', lzma.decompress)]:
        try:
            o = f(b)
            if len(o) > 64:
                return f'{m}->{len(o)}B first={o[:16].hex()}'
        except Exception:
            pass
    return None

hits = 0
for kn, key in KEYS.items():
    for klen in (16, 24, 32):
        if len(key) < klen:
            continue
        k = key[:klen]
        # choose IVs: full 16-byte ones only for CBC/CFB/OFB
        for ivn, iv in [(n, KEYS[n]) for n in IVS if len(KEYS[n]) >= 16]:
            iv16 = iv[:16]
            for mode, mn in [(AES.MODE_CBC, 'CBC'), (AES.MODE_CFB, 'CFB'), (AES.MODE_OFB, 'OFB')]:
                for fn, data in files.items():
                    try:
                        c = AES.new(k, mode, iv=iv16)
                        out = c.decrypt(data[:len(data)//16*16])
                        r = looks_good(out, fn)
                        if r:
                            print(f"[HIT] key={kn} klen={klen} iv={ivn} {mn} file={fn}: {r}")
                            hits += 1
                    except Exception:
                        pass
            # CTR with iv as initial counter (big-endian 16 bytes) and byte-oriented variants
            for mode, mn in [(AES.MODE_CTR, 'CTR')]:
                for fn, data in files.items():
                    try:
                        ctr = int.from_bytes(iv16, 'big')
                        c = AES.new(k, AES.MODE_CTR, nonce=b'', initial_value=ctr)
                        out = c.decrypt(data)
                        r = looks_good(out, fn)
                        if r:
                            print(f"[HIT] key={kn} klen={klen} iv={ivn} {mn} file={fn}: {r}")
                            hits += 1
                    except Exception:
                        pass
            # CTR little-endian
            for fn, data in files.items():
                try:
                    ctr = int.from_bytes(iv16, 'little')
                    c = AES.new(k, AES.MODE_CTR, nonce=b'', initial_value=ctr)
                    out = c.decrypt(data)
                    r = looks_good(out, fn)
                    if r:
                        print(f"[HIT] key={kn} klen={klen} iv={ivn} CTR-LE file={fn}: {r}")
                        hits += 1
                except Exception:
                    pass
        # ECB
        for fn, data in files.items():
            try:
                c = AES.new(k, AES.MODE_ECB)
                out = c.decrypt(data[:len(data)//16*16])
                r = looks_good(out, fn)
                if r:
                    print(f"[HIT] key={kn} klen={klen} ECB file={fn}: {r}")
                    hits += 1
            except Exception:
                pass

print(f"\ndone. {hits} hits")
