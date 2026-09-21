#!/usr/bin/env python3
"""Decrypt all captured API responses (login/gameinfo/myinfo/pattern) with the session key."""
import base64, json, os, gzip, zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Session keys rotate per launch and are never committed; supply the session
# that produced your captures:
#   EZ2_API_SESSION_KEY / EZ2_API_SESSION_IV   (ASCII zf.aes_key / zf.aes_iv)
#   EZ2_BUNDLE_CRYPT_KEY                       (base64 bundleCryptKey)
KEY = os.environ.get('EZ2_API_SESSION_KEY', '').encode()
IV  = os.environ.get('EZ2_API_SESSION_IV', '').encode()

def b64d(s):
    s = ''.join(s.split())
    return base64.b64decode(s + '=' * (-len(s) % 4))

def try_dec(name, data):
    print(f"\n===== {name}: {len(data)} bytes, %16={len(data)%16} =====")
    variants = [('whole', data)]
    for off in (1, 2, 4, 8, 16):
        if len(data) > off: variants.append((f'[{off}:]', data[off:]))
    for vname, d in variants:
        if len(d) < 16: continue
        ct = d[:len(d)//16*16]
        try:
            pt = AES.new(KEY, AES.MODE_CBC, iv=IV).decrypt(ct)
            # try unpad
            try: body = unpad(pt, 16)
            except Exception: body = pt
            pr = sum(1 for c in body[:200] if 9 <= c < 127) / max(1, min(200, len(body)))
            if pr > 0.7 or body[:2] in (b'\x1f\x8b', b'x\x9c'):
                txt = body
                dec = None
                for mn, fn in [('gzip', gzip.decompress), ('zlib', zlib.decompress), ('raw', lambda x: zlib.decompress(x, -15))]:
                    try:
                        dec = fn(body); break
                    except Exception: pass
                print(f"  [OK {vname}] printable={pr:.2f} first200={body[:200]!r}")
                if dec is not None:
                    print(f"      -> decompressed({mn}): {len(dec)} bytes: {dec[:300]!r}")
                return body
        except Exception as e:
            pass
    print("  no clean CBC decryption")
    return None

for name in ['c2s_login.bin', 'c2s_get_myinfo.bin', 'c2s_get_gameinfo.bin']:
    p = os.path.join('mitm_parsed', name)
    if os.path.exists(p):
        raw = open(p, 'rb').read()
        try_dec(name, b64d(raw.decode()))
    else:
        print(f"{name}: not found")
