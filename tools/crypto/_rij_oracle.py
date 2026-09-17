import sys, json, base64, hashlib
sys.path.insert(0,'.')
from _rijsearch import make_dec
CHART = open('mitm_live/cdn_b2e7d53430783e02.bin','rb').read()
IDX   = open('mitm_live/cdn_69cfeccf55085d5f.bin','rb').read()
H_CHART='cc37e297d906a89946f20e12f9fd8f4faef55444b895fd40339ca8dce766c9'
H_IDX  ='164258983dc5674dc27b12102287c144998076dfbe2e7f0bbfc03dd04ed5c4'
MK = base64.b64decode('VEA290wJVPxMQ/NAjbMPe8PXiPsuqMExSvtwd9j6u3JoCNh/hpeZvod4Z/ZpP221')
strs=json.load(open('_strs_a.json')); sweep=json.load(open('_allsweep.json'))
keys={}
keys['rjn[0:16]']=MK[0:16]; keys['rjn[16:32]']=MK[16:32]; keys['rjn[32:48]']=MK[32:48]
for o in range(0,33): keys['rjn[%d:%d]'%(o,o+16)]=MK[o:o+16]
for k,v in strs.items():
    if not isinstance(v,str): continue
    v=v.strip('"')
    if len(v) in (16,24,32) and all(32<=ord(c)<127 for c in v): keys['S:'+k]=v.encode()
    if v.endswith('=') and len(v) in (24,44,64,88):
        try:
            d=base64.b64decode(v,validate=True)
            if len(d) in (16,24,32): keys['B:'+k]=d
        except Exception: pass
for x in sweep['bytes']:
    b=bytes.fromhex(x['hex'])
    for L in (16,24,32):
        for o in range(0,max(1,len(b)-L+1)):
            if len(b)>=L: keys['FW:%s.%s[%d]'%(x['cls'],x['field'],o)]=b[o:o+L]
for x in sweep['strings']:
    s=x['s']
    if len(s) in (16,24,32) and all(32<=ord(c)<127 for c in s): keys['T:'+x['cls']+'.'+x['field']]=s.encode()
    if s.endswith('=') and len(s) in (24,44,64,88):
        try:
            d=base64.b64decode(s,validate=True)
            if len(d) in (16,24,32): keys['TB:'+x['cls']+'.'+x['field']]=d
        except Exception: pass
for s in list(set(keys.values())):
    for fn in (hashlib.md5,hashlib.sha1,hashlib.sha256):
        h=fn(s).digest()
        for L in (16,24,32):
            if len(h)>=L: keys['H%d:%s'%(L,fn().name)]=h[:L]
print('keys:', len(keys))
def padn(b, bs):
    n = b[-1]
    return n if 1 <= n <= bs and b[-n:] == bytes([n])*n else None
def run(bs, data, tag, hits):
    Cn = data[-bs:]; Cp = data[-2*bs:-bs]
    for kn, key in keys.items():
        try: dec = make_dec(key, bs//4)
        except Exception: continue
        p = bytes(x ^ y for x, y in zip(dec(Cn), Cp))
        n = padn(p, bs)
        if n: hits.append((tag, kn, key.hex(), n, p.hex()))
hits=[]
for bs in (8, 4):     # 32-byte block first, then 16-byte
    run(bs, CHART, 'CHART', hits)
    run(bs, IDX,   'IDX',   hits)
print('padding-valid candidates:', len(hits))
for h in hits[:25]:
    print('   bs=%d %s %-22s key=%s pad=%d' % (h[3]*0+h[3], h[0], h[1][:22], h[2][:32], h[3]))
