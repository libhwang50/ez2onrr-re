#!/usr/bin/env python3
"""Hypothesis: bundleCryptKey (48 B) is an ENCRYPTED AesKeyJson, unwrapped with a
static key (da/qe/zf) to yield [32-byte CDN key][16-byte CDN IV]. Then decrypt CDN."""
import base64, glob, itertools, os
from Crypto.Cipher import AES

BCK = os.environ.get('EZ2_BUNDLE_CRYPT_KEY', '')
BCK_RAW = base64.b64decode(BCK + '=' * (-len(BCK) % 4))
def hx(s): return bytes.fromhex(s)

# wrap-key candidates (old session zf key + static da/qe + metadata defaults)
WRAP = {
    'da_ascii': (b'91534567190123456709012745679903', b'0173456089512849'),
    'qe_ascii': (b'31274527810126456489012345678909', b'9824450789003347'),
    # old-session zf key: supply via EZ2_API_SESSION_KEY / EZ2_API_SESSION_IV
    'zf_ascii_old': (os.environ.get('EZ2_API_SESSION_KEY', '').encode(),
                     os.environ.get('EZ2_API_SESSION_IV', '').encode()),
    'zf_hex_old': (hx(os.environ.get('EZ2_API_SESSION_KEY', '')),
                   hx(os.environ.get('EZ2_API_SESSION_IV', ''))),
    'zf_default_ascii': (b'4A6469F1358147858EFD430E44FD8A57', b'F8BECB8836AFA814'),
    'zf_default_hex': (hx('4A6469F1358147858EFD430E44FD8A57'), hx('F8BECB8836AFA814')),
}

def ezff(b): return b[:4] == b'EZFF'
def ez_ok(b):
    if len(b) < 64: return False
    pr = sum(1 for c in b[:256] if 9 <= c < 127) / 256
    s = b[:256].decode('latin-1', 'ignore')
    return pr > 0.95 and s.count(' ') >= 5

engine = open(glob.glob('mitm_parsed/cdn_018_*.bin')[0], 'rb').read()

def try_cdn(keyiv, tag):
    for order, (k, iv) in [('K+V', (keyiv[:32], keyiv[32:48])), ('V+K', (keyiv[16:48], keyiv[0:16]))]:
        if len(k) not in (16, 24, 32) or len(iv) != 16: continue
        for mode, mn in [(AES.MODE_CBC, 'CBC'), (AES.MODE_CFB, 'CFB'), (AES.MODE_OFB, 'OFB'), (AES.MODE_ECB, 'ECB')]:
            try:
                c = AES.new(k, mode, iv=iv) if mode != AES.MODE_ECB else AES.new(k, mode)
                out = c.decrypt(engine[:len(engine)//16*16] if mode in (AES.MODE_CBC, AES.MODE_ECB) else engine)
                if ezff(out) or ez_ok(out):
                    print(f"[HIT!] wrap={tag} order={order} mode={mn}: {out[:80]!r}")
                    return True
            except Exception: pass
    return False

hits = 0
for wkname, (wkey, wiv) in WRAP.items():
    for klen in (16, 24, 32):
        if len(wkey) < klen: continue
        k = wkey[:klen]
        for iv16 in (wiv[:16], wiv.ljust(16, b'\0')[:16], b'\0'*16):
            for mode, mn in [(AES.MODE_CBC, 'CBC'), (AES.MODE_ECB, 'ECB')]:
                try:
                    c = AES.new(k, mode, iv=iv16) if mode != AES.MODE_ECB else AES.new(k, mode)
                    unwrapped = c.decrypt(BCK_RAW)
                    print(f"unwrap wrap={wkname}[{klen}] {mn}: {unwrapped.hex()}")
                    if try_cdn(unwrapped, f'{wkname}[{klen}]{mn}'):
                        hits += 1
                except Exception as e:
                    pass
print(f"done, {hits} hits")
