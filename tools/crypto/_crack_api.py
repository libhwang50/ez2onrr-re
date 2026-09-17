#!/usr/bin/env python3
"""Brute-force decrypt the c2s_get_pattern_file API request/response bodies."""
import json, base64, urllib.parse, glob, os
from Crypto.Cipher import AES

def hx(s): return bytes.fromhex(s)

# session key material (live, this session)
RAW = {
    'svk': hx('b6267ea195763df32ec91ed39d7f66035ca002de4dee12fff9cf93ed92163e0d'),
    'svl': hx('8c8e78a8cae9885cc5438b58e2931609'),
    'svm': hx('1c041e8ebb58fdb485deb781fa756696a45ff1bf1ba7d9e85663a01c62bb1f2b'),
    'svn': hx('8e763cd2a4d409d62658d626c06f027c'),
    'svo': hx('7dbb2047f7def50c7c30a7709f6b4bac1dc3aebee52f455fe801a32b29518b1d'),
    'svp': hx('0d1a6bcb9c80f1b53bdaf766ed40012f'),
    'svq': hx('31a3e172df7b44db465c84ad28f5a5a59875772fab5a062a8c2e44cfe8a5ba441e68ecdb8ccdfcce716c5268f09754904192c9912759d1780a7a7705737fc6ca'),
    'svr': hx('d0d9223422c56c6ce10496cc0a44777d'),
    # static defaults (metadata-embedded)
    'zf_aes_key_hex16': hx('4A6469F1358147858EFD430E44FD8A57'),
    'zf_aes_iv_hex8': hx('F8BECB8836AFA814'),
    'zf_aes_key_ascii': b'4A6469F1358147858EFD430E44FD8A57',
    'zf_aes_iv_ascii': b'F8BECB8836AFA814',
    'da_aes_key': b'91534567190123456709012745679903',
    'da_aes_iv': b'0173456089512849',
    'qe_aes_key': b'31274527810126456489012345678909',
    'qe_aes_iv': b'9824450789003347',
}

def looks_json(b):
    if not b: return None
    s = b.decode('utf-8', 'ignore')
    if s.strip().startswith('{') and ('final_url' in s or 'appid' in s or 'musicresourcename' in s or 'keymode' in s or 'result' in s):
        return s[:300]
    # loose: just printable + contains '{'
    pr = sum(1 for c in b[:200] if 32 <= c < 127) / min(200, len(b))
    if pr > 0.9 and b'{' in b:
        return s[:300]
    return None

def try_dec(data, label):
    for kn, key in RAW.items():
        for klen in (16, 24, 32):
            if len(key) < klen: continue
            k = key[:klen]
            iv_cands = {kn: key for kn, key in RAW.items()}
            for ivn, iv in iv_cands.items():
                for ivlen in (8, 16):
                    if len(iv) < ivlen: continue
                    ivv = iv[:ivlen]
                    # CBC/CFB/OFB need iv==block 16
                    for mode, mn in [(AES.MODE_CBC, 'CBC'), (AES.MODE_CFB, 'CFB'), (AES.MODE_OFB, 'OFB')]:
                        if ivlen != 16: continue
                        for variant, fn in [(f"{mn}-{ivn}{ivlen}", lambda c: c.decrypt(data[:len(data)//16*16]))]:
                            try:
                                c = AES.new(k, mode, iv=ivv)
                                out = fn(c)
                                r = looks_json(out)
                                if r:
                                    print(f"[HIT] key={kn}[{klen}] iv={ivn}[{ivlen}] {mn} on {label}: {r}")
                                    return out
                            except Exception: pass
                    # CTR with iv as counter
                    try:
                        ctr = int.from_bytes(ivv, 'big')
                        c = AES.new(k, AES.MODE_CTR, nonce=b'', initial_value=ctr)
                        out = c.decrypt(data)
                        r = looks_json(out)
                        if r:
                            print(f"[HIT] key={kn}[{klen}] iv={ivn}[{ivlen}] CTR-BE on {label}: {r}")
                            return out
                    except Exception: pass
                    try:
                        ctr = int.from_bytes(ivv, 'little')
                        c = AES.new(k, AES.MODE_CTR, nonce=b'', initial_value=ctr)
                        out = c.decrypt(data)
                        r = looks_json(out)
                        if r:
                            print(f"[HIT] key={kn}[{klen}] iv={ivn}[{ivlen}] CTR-LE on {label}: {r}")
                            return out
                    except Exception: pass
        # ECB
        try:
            c = AES.new(k, AES.MODE_ECB)
            out = c.decrypt(data[:len(data)//16*16])
            r = looks_json(out)
            if r:
                print(f"[HIT] key={kn}[{klen}] ECB on {label}: {r}")
                return out
        except Exception: pass
    return None

# load one pattern flow
f = sorted(glob.glob('mitm_parsed/pattern_*.json'))[0]
d = json.load(open(f))
req_data = urllib.parse.unquote(d['req_body_text'].split('data=',1)[1])
req_raw = base64.urlsafe_b64decode(req_data + '='*(-len(req_data)%4))
resp_raw = base64.b64decode(d['resp_body_text'].strip() + '='*(-len(d['resp_body_text'].strip())%4))

print(f"=== {f} ===")
print(f"req_raw len={len(req_raw)}")
print(f"resp_raw len={len(resp_raw)}")
print("\n--- trying request ---")
r1 = try_dec(req_raw, 'request')
print("\n--- trying response ---")
r2 = try_dec(resp_raw, 'response')
