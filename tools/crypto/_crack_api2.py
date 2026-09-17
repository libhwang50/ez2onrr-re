#!/usr/bin/env python3
"""Crack the API session cipher: stream mode (CTR/CFB/OFB) with fixed IV
d3ad76d3adb846d599fae4c451509c06, key from harvested session material."""
import json, base64, urllib.parse, glob
from Crypto.Cipher import AES

def hx(s): return bytes.fromhex(s)

RAW = {
    'svk': hx('b6267ea195763df32ec91ed39d7f66035ca002de4dee12fff9cf93ed92163e0d'),
    'svl': hx('8c8e78a8cae9885cc5438b58e2931609'),
    'svm': hx('1c041e8ebb58fdb485deb781fa756696a45ff1bf1ba7d9e85663a01c62bb1f2b'),
    'svn': hx('8e763cd2a4d409d62658d626c06f027c'),
    'svo': hx('7dbb2047f7def50c7c30a7709f6b4bac1dc3aebee52f455fe801a32b29518b1d'),
    'svp': hx('0d1a6bcb9c80f1b53bdaf766ed40012f'),
    'svq': hx('31a3e172df7b44db465c84ad28f5a5a59875772fab5a062a8c2e44cfe8a5ba441e68ecdb8ccdfcce716c5268f09754904192c9912759d1780a7a7705737fc6ca'),
    'svr': hx('d0d9223422c56c6ce10496cc0a44777d'),
    'zf_aes_key_hex': hx('4A6469F1358147858EFD430E44FD8A57'),
    'zf_aes_iv_hex': hx('F8BECB8836AFA814'),
    'zf_aes_key_ascii': b'4A6469F1358147858EFD430E44FD8A57',
    'zf_aes_iv_ascii': b'F8BECB8836AFA814',
    'da_aes_key': b'91534567190123456709012745679903',
    'da_aes_iv': b'0173456089512849',
    'qe_aes_key': b'31274527810126456489012345678909',
    'qe_aes_iv': b'9824450789003347',
}

FIXED_IV = hx('d3ad76d3adb846d599fae4c451509c06')

def looks_json(b):
    if not b: return None
    try:
        s = b.decode('utf-8', 'ignore')
    except Exception:
        return None
    t = s.strip()
    if t.startswith('{') and ('final_url' in s or 'appid' in s or 'musicresourcename' in s or 'keymode' in s or 'result' in s or 'bundleCryptKey' in s or 'MEMBER_ID' in s or 'AES_KEY' in s):
        return s[:400]
    pr = sum(1 for c in b[:300] if 32 <= c < 127) / min(300, len(b))
    if pr > 0.85 and b'{' in b:
        return s[:400]
    return None

def try_keys(data, label, ivs):
    hits = []
    for kn, key in RAW.items():
        for klen in (16, 24, 32):
            if len(key) < klen: continue
            k = key[:klen]
            for ivn, iv in ivs:
                for ivlen in (16,):
                    if len(iv) < ivlen: continue
                    iv16 = iv[:16]
                    # CFB/OFB with iv
                    for mode, mn, kw in [(AES.MODE_CFB, 'CFB128', {}), (AES.MODE_OFB, 'OFB', {})]:
                        try:
                            c = AES.new(k, mode, iv=iv16, **kw)
                            out = c.decrypt(data)
                            r = looks_json(out)
                            if r:
                                hits.append(f"[HIT] key={kn}[{klen}] iv={ivn} {mn} on {label}: {r}")
                        except Exception: pass
                    # CFB with segment_size 8
                    try:
                        c = AES.new(k, AES.MODE_CFB, iv=iv16, segment_size=8)
                        out = c.decrypt(data)
                        r = looks_json(out)
                        if r:
                            hits.append(f"[HIT] key={kn}[{klen}] iv={ivn} CFB8 on {label}: {r}")
                    except Exception: pass
                    # CTR: counter = iv, incrementing last byte (standard), and first byte
                    for order in ('big', 'little'):
                        try:
                            ctr = int.from_bytes(iv16, order)
                            c = AES.new(k, AES.MODE_CTR, nonce=b'', initial_value=ctr)
                            out = c.decrypt(data)
                            r = looks_json(out)
                            if r:
                                hits.append(f"[HIT] key={kn}[{klen}] iv={ivn} CTR-{order} on {label}: {r}")
                        except Exception: pass
                    # CTR with 8-byte nonce + 8-byte counter
                    try:
                        c = AES.new(k, AES.MODE_CTR, nonce=iv16[:8], initial_value=int.from_bytes(iv16[8:], 'big'))
                        out = c.decrypt(data)
                        r = looks_json(out)
                        if r:
                            hits.append(f"[HIT] key={kn}[{klen}] iv={ivn} CTR-nonce8 on {label}: {r}")
                    except Exception: pass
    return hits

# load pattern flow
f = sorted(glob.glob('mitm_parsed/pattern_*.json'))[0]
d = json.load(open(f))
req_data = urllib.parse.unquote(d['req_body_text'].split('data=',1)[1])
req_raw = base64.urlsafe_b64decode(req_data + '='*(-len(req_data)%4))
resp_raw = base64.b64decode(d['resp_body_text'].strip() + '='*(-len(d['resp_body_text'].strip())%4))

print(f"req_raw len={len(req_raw)}  resp_raw len={len(resp_raw)}")
print(f"req IV (first 16) = {req_raw[:16].hex()}")

# interpretation A: request = IV(16) + ciphertext ; response = ciphertext (implicit IV)
ivs = [('fixed', FIXED_IV)] + [(k, v) for k, v in RAW.items() if len(v) >= 16]

print("\n=== A: req[16:] as ciphertext, fixed IV ===")
for h in try_keys(req_raw[16:], 'request[16:]', ivs):
    print(h)

print("\n=== A: response as ciphertext, fixed IV ===")
for h in try_keys(resp_raw, 'response', ivs):
    print(h)

# interpretation B: no prepended IV, use whole data as ciphertext with candidate IVs
print("\n=== B: whole request as ciphertext ===")
for h in try_keys(req_raw, 'request-whole', ivs):
    print(h)
print("\n=== B: whole response as ciphertext ===")
for h in try_keys(resp_raw, 'response-whole', ivs):
    print(h)
print("\ndone")
