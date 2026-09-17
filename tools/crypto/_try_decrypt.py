import itertools, zlib, gzip, lzma
from Crypto.Cipher import AES

files = {
 'ez':  open('extracted_charts/5dae1cc7be12209ba540c0234b64ff8d1e672e540ab0bcfc09c8a0941bcb6e.ez','rb').read(),
 'ezi': open('extracted_charts/4f3a20b5d9c489b435a74e985db2d1c299a0b51ecb896280e6cc43c18b5b0a.ezi','rb').read(),
}

# live keys harvested from RAM
cands = {
 'da.aes_key/iv (ascii32/16)': (b'91534567190123456709012745679903', b'0173456089512849'),
 'qe.aes_key/iv (ascii32/16)': (b'31274527810126456489012345678909', b'9824450789003347'),
 'zf.aes_key hex16/iv hex8':   (bytes.fromhex('4A6469F1358147858EFD430E44FD8A57'), bytes.fromhex('F8BECB8836AFA814')),
 'zf.aes_key ascii32/iv ascii16': (b'4A6469F1358147858EFD430E44FD8A57', b'F8BECB8836AFA814'),
}

def looks_good(b):
    if not b: return None
    if b[:4]==b'EZFF': return 'EZFF!'
    for m,f in [('gzip',gzip.decompress),('zlib',zlib.decompress),('deflate',lambda x:zlib.decompress(x,-15)),('lzma',lzma.decompress)]:
        try:
            o=f(b)
            if len(o)>64: return f'{m}->{len(o)}B first={o[:12].hex()}'
        except Exception: pass
    # high printable ascii ratio (for .ez)
    pr=sum(1 for c in b[:400] if 9<=c<127)/min(400,len(b))
    if pr>0.95: return f'ASCII {pr:.2f} first={b[:48]!r}'
    return None

for label,(key,iv) in cands.items():
    for klen in (16,24,32):
        k = key[:klen] if len(key)>=klen else key.ljust(klen, b'\0')
        if len(k)!=klen: continue
        for mode,mn in [(AES.MODE_CBC,'CBC'),(AES.MODE_ECB,'ECB'),(AES.MODE_CFB,'CFB'),(AES.MODE_OFB,'OFB'),(AES.MODE_CTR,'CTR')]:
            for fn,data in files.items():
                try:
                    if mn=='ECB':
                        c=AES.new(k,AES.MODE_ECB); out=c.decrypt(data[:len(data)//16*16])
                    elif mn=='CTR':
                        c=AES.new(k,AES.MODE_CTR,nonce=b'',initial_value=int.from_bytes(iv[:8],'big') if len(iv)>=8 else 0); out=c.decrypt(data)
                    else:
                        ivv=iv[:16].ljust(16,b'\0')
                        c=AES.new(k,mode,iv=ivv); out=c.decrypt(data[:len(data)//16*16])
                    r=looks_good(out)
                    if r:
                        print(f"[HIT] {label} {mn} klen={klen} file={fn}: {r}")
                except Exception as e:
                    pass
print("done")
