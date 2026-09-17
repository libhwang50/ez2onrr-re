# Rijndael with a 256-bit block (Nb=8), 128-bit key (Nk=4), Nr=14 - as used by InGameCore.dcg
SBOX = bytes.fromhex(
 '637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0'
 'b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275'
 '09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf'
 'd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2'
 'cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb'
 'e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08'
 'ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e'
 'e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16')
RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d,0x9a]
Nb, Nk, Nr = 8, 4, 14
def xtime(a): return ((a<<1) ^ 0x1b) & 0xff if a & 0x80 else (a<<1) & 0xff
def mul(a,b):
    r=0
    while b:
        if b&1: r^=a
        a=xtime(a); b>>=1
    return r
def expand_key(key):
    w=[list(key[4*i:4*i+4]) for i in range(Nk)]
    for i in range(Nk, Nb*(Nr+1)):
        t=list(w[i-1])
        if i % Nk == 0:
            t=t[1:]+t[:1]
            t=[SBOX[b] for b in t]
            t[0]^=RCON[i//Nk-1]
        w.append([w[i-Nk][j]^t[j] for j in range(4)])
    return w
def add_rk(s,w,rnd):
    for c in range(Nb):
        for j in range(4):
            s[4*c+j]^=w[rnd*Nb+c][j]
def shift_rows(s, inv=False):
    # state: s[4*c + r] = byte at row r, col c  (Nb=8)
    shifts=[0,1,3,4]
    for r in range(4):
        sh=shifts[r]
        row=[s[4*c+r] for c in range(Nb)]
        if inv: row=row[-sh:]+row[:-sh] if sh else row
        else:   row=row[sh:]+row[:sh] if sh else row
        for c in range(Nb): s[4*c+r]=row[c]
def mix_columns(s, inv=False):
    m = [[14,11,13,9],[9,14,11,13],[13,9,14,11],[11,13,9,14]] if inv else \
        [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]
    for c in range(Nb):
        col=[s[4*c+j] for j in range(4)]
        for j in range(4):
            s[4*c+j]=mul(m[j][0],col[0])^mul(m[j][1],col[1])^mul(m[j][2],col[2])^mul(m[j][3],col[3])
def decrypt_block(blk, w):
    s=list(blk); add_rk(s,w,Nr)
    for rnd in range(Nr-1,-1,-1):
        shift_rows(s,inv=True)
        s=[SBOX.index(b) if False else None for b in s]  # placeholder
    return bytes(s)
INV_SBOX=bytes(SBOX.index(i) for i in range(256))
def decrypt_block(blk, w):
    s=list(blk); add_rk(s,w,Nr)
    for rnd in range(Nr-1,-1,-1):
        shift_rows(s,inv=True)
        s=[INV_SBOX[b] for b in s]
        add_rk(s,w,rnd)
        if rnd>0: mix_columns(s,inv=True)
    return bytes(s)
def cbc_decrypt(data, key, iv):
    w=expand_key(key); out=bytearray(); prev=iv
    for i in range(0,len(data)-len(data)%32,32):
        b=data[i:i+32]
        p=decrypt_block(b,w)
        out+=bytes(x^y for x,y in zip(p,prev))
        prev=b
    return bytes(out)
def unpad_pkcs7(b):
    if not b: return b
    n=b[-1]
    if 1<=n<=32 and b[-n:]==bytes([n])*n: return b[:-n]
    return b
