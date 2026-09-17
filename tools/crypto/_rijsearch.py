import sys, json, base64, hashlib
sys.path.insert(0,'.')
import _rijndael256 as m
SBOX=m.SBOX; INV=m.INV_SBOX; mul=m.mul
RCON=[0]*64; r=1
for i in range(1,64):
    RCON[i]=r; r=((r<<1)^0x1b)&0xff if r&0x80 else (r<<1)&0xff

def expand(key,Nb):
    Nk=len(key)//4; Nr=max(Nb,Nk)+6
    w=[list(key[4*i:4*i+4]) for i in range(Nk)]
    for i in range(Nk,Nb*(Nr+1)):
        t=list(w[i-1])
        if i%Nk==0:
            t=t[1:]+t[:1]; t=[SBOX[b] for b in t]; t[0]^=RCON[i//Nk]
        elif Nk>6 and i%Nk==4: t=[SBOX[b] for b in t]
        w.append([w[i-Nk][j]^t[j] for j in range(4)])
    return w,Nr
def shift(s,Nb,inv):
    for r0 in range(4):
        k=[0,1,2,3][r0] if Nb==4 else [0,1,3,4][r0]
        if not k: continue
        row=[s[4*c+r0] for c in range(Nb)]
        row=row[-k:]+row[:-k] if inv else row[k:]+row[:k]
        for c in range(Nb): s[4*c+r0]=row[c]
def mixcol(s,Nb,inv):
    mm=[[14,11,13,9],[9,14,11,13],[13,9,14,11],[11,13,9,14]] if inv else [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]
    for c in range(Nb):
        col=[s[4*c+j] for j in range(4)]
        for j in range(4): s[4*c+j]=mul(mm[j][0],col[0])^mul(mm[j][1],col[1])^mul(mm[j][2],col[2])^mul(mm[j][3],col[3])
def addrk(s,w,r,Nb):
    for c in range(Nb):
        for j in range(4): s[4*c+j]^=w[r*Nb+c][j]
def make_dec(key,Nb):
    w,Nr=expand(key,Nb)
    def f(b):
        s=list(b); addrk(s,w,Nr,Nb)
        for r in range(Nr-1,-1,-1):
            shift(s,Nb,True); s=[INV[x] for x in s]; addrk(s,w,r,Nb)
            if r>0: mixcol(s,Nb,True)
        return bytes(s)
    return f
def printable(b): return sum(1 for c in b if 9<=c<127)
