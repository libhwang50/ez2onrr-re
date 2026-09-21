#!/usr/bin/env python3
"""Crack the API session cipher with the RUNTIME zf.aes_key/aes_iv session keys."""
import json, base64, urllib.parse, glob, os
from Crypto.Cipher import AES

def hx(s): return bytes.fromhex(s)

# Session keys rotate per launch and are never committed; supply the session
# that produced your captures:
#   EZ2_API_SESSION_KEY / EZ2_API_SESSION_IV   (ASCII zf.aes_key / zf.aes_iv)
#   EZ2_BUNDLE_CRYPT_KEY                       (base64 bundleCryptKey)
ZF_KEY_HEX = os.environ.get('EZ2_API_SESSION_KEY', '')
ZF_IV_HEX  = os.environ.get('EZ2_API_SESSION_IV', '')
FIXED_IV   = hx('d3ad76d3adb846d599fae4c451509c06')

KEYS = {
    'zf_hex': hx(ZF_KEY_HEX),            # 16 bytes
    'zf_ascii': ZF_KEY_HEX.encode(),      # 32 bytes
    'zf_hex32pad': hx(ZF_KEY_HEX + '00'*16),  # 32 bytes (hex of 32)
}
IVS = {
    'zf_iv_hex': hx(ZF_IV_HEX),           # 8 bytes
    'zf_iv_ascii': ZF_IV_HEX.encode(),    # 16 bytes
    'zf_key_hex16': hx(ZF_KEY_HEX),       # 16
    'fixed': FIXED_IV,                    # 16
    'zero16': b'\x00'*16,
    'zero8': b'\x00'*8,
}

def looks_json(b):
    if not b: return None
    s = b.decode('utf-8', 'ignore')
    t = s.strip()
    if t.startswith('{') and ('final_url' in s or 'appid' in s or 'musicresourcename' in s or 'keymode' in s or 'result' in s or 'bundleCryptKey' in s or 'MEMBER_ID' in s or 'AES_KEY' in s or 'DLC' in s):
        return s[:500]
    pr = sum(1 for c in b[:300] if 32 <= c < 127) / min(300, len(b))
    if pr > 0.9 and (b'{' in b or b'"' in b):
        return s[:500]
    return None

def attempt(data, label):
    hits = []
    for kn, key in KEYS.items():
        for klen in (16, 32):
            if len(key) < klen: continue
            k = key[:klen]
            for ivn, iv in IVS.items():
                for ivlen in (8, 16):
                    if len(iv) < ivlen: continue
                    ivv = iv[:ivlen]
                    # CBC/CFB/OFB (need 16-byte iv)
                    if ivlen == 16:
                        for mode, mn in [(AES.MODE_CBC, 'CBC'), (AES.MODE_CFB, 'CFB128'), (AES.MODE_OFB, 'OFB')]:
                            try:
                                c = AES.new(k, mode, iv=ivv)
                                out = c.decrypt(data[:len(data)//16*16] if mode == AES.MODE_CBC else data)
                                r = looks_json(out)
                                if r: hits.append(f"[HIT] key={kn}[{klen}] iv={ivn}[{ivlen}] {mn} {label}: {r}")
                            except Exception: pass
                        try:
                            c = AES.new(k, AES.MODE_CFB, iv=ivv, segment_size=8)
                            out = c.decrypt(data)
                            r = looks_json(out)
                            if r: hits.append(f"[HIT] key={kn}[{klen}] iv={ivn}[{ivlen}] CFB8 {label}: {r}")
                        except Exception: pass
                    # CTR variants
                    try:
                        c = AES.new(k, AES.MODE_CTR, nonce=b'', initial_value=int.from_bytes(ivv.ljust(8, b'\0'), 'big'))
                        out = c.decrypt(data); r = looks_json(out)
                        if r: hits.append(f"[HIT] key={kn}[{klen}] iv={ivn}[{ivlen}] CTR-BE {label}: {r}")
                    except Exception: pass
                    try:
                        c = AES.new(k, AES.MODE_CTR, nonce=b'', initial_value=int.from_bytes(ivv.ljust(8, b'\0'), 'little'))
                        out = c.decrypt(data); r = looks_json(out)
                        if r: hits.append(f"[HIT] key={kn}[{klen}] iv={ivn}[{ivlen}] CTR-LE {label}: {r}")
                    except Exception: pass
            # ECB
            try:
                c = AES.new(k, AES.MODE_ECB)
                out = c.decrypt(data[:len(data)//16*16]); r = looks_json(out)
                if r: hits.append(f"[HIT] key={kn}[{klen}] ECB {label}: {r}")
            except Exception: pass
    return hits

f = sorted(glob.glob('mitm_parsed/pattern_*.json'))[0]
d = json.load(open(f))
req_data = urllib.parse.unquote(d['req_body_text'].split('data=', 1)[1])
req_raw = base64.urlsafe_b64decode(req_data + '='*(-len(req_data) % 4))
resp_raw = base64.b64decode(d['resp_body_text'].strip() + '='*(-len(d['resp_body_text'].strip()) % 4))

print(f"key_hex={ZF_KEY_HEX} iv_hex={ZF_IV_HEX}")
print(f"req len={len(req_raw)} resp len={len(resp_raw)}")

for label, data in [('req-all', req_raw), ('req[16:]', req_raw[16:]), ('resp-all', resp_raw), ('req[0:16]+resp', req_raw[:16]+resp_raw)]:
    print(f"\n--- {label} ---")
    for h in attempt(data, label):
        print("  " + h)
print("\ndone")
