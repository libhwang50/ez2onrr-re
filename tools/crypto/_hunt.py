import json, base64, hashlib, sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
CHART = open('mitm_live/cdn_b2e7d53430783e02.bin','rb').read()   # 56000 B = CHART
IDX   = open('mitm_live/cdn_69cfeccf55085d5f.bin','rb').read()   # 18192 B = index
H_CHART='cc37e297d906a89946f20e12f9fd8f4faef55444b895fd40339ca8dce766c9'
H_IDX  ='164258983dc5674dc27b12102287c144998076dfbe2e7f0bbfc03dd04ed5c4'
strs = json.load(open('_strs_a.json'))
cands = {}
for k,v in strs.items():
    if not isinstance(v,str): continue
    v = v.strip('"')
    if len(v) in (16,24,32) and all(32<=ord(c)<127 for c in v):
        cands['S:'+k] = v.encode()
    if v.endswith('=') and len(v) in (24,44,64,88):
        try:
            d = base64.b64decode(v, validate=True)
            if len(d) in (16,24,32): cands['B:'+k] = d
        except Exception: pass
print('candidate keys:', len(cands))
def variants(pt):
    yield 'raw', pt
    try:
        u = unpad(pt,16)
        if u != pt: yield 'pkcs7', u
    except Exception: pass
    if pt and pt[-1]==0: yield 'rzero', pt.rstrip(b'\x00')
hits=[]; n=0
for kn, key in cands.items():
    ivlist = [('zero', b'\0'*16)]
    if len(key)>=16: ivlist.append(('kpfx', key[:16]))
    ivlist.append(('objpfx', CHART[:16]))
    for ivn, iv in ivlist:
        for mode,mn in ((AES.MODE_CBC,'CBC'),(AES.MODE_ECB,'ECB'),(AES.MODE_CFB,'CFB'),(AES.MODE_OFB,'OFB')):
            for off in (0,16):
                for data,h,tag in ((CHART,H_CHART,'CHART'),(IDX,H_IDX,'IDX')):
                    n += 1
                    try:
                        c = AES.new(key,mode) if mn=='ECB' else AES.new(key,mode,iv=iv)
                        pt = c.decrypt(data[off:])
                    except Exception: continue
                    for vn,cand in variants(pt):
                        full = data[:off]+cand if off else cand
                        if hashlib.sha256(full).hexdigest()==h:
                            hits.append((tag,kn,ivn,mn,off,vn,len(full)))
print('attempts:', n)
for x in hits: print('*** MATCH ***', x)
if not hits: print('no sha256 match')
