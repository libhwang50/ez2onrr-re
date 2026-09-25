#!/usr/bin/env python3
"""Read the running client's live rating state through the harvester's single
Frida session (server/re/_harvest_session.py must be attached).

    python server/re/_rating_live.py            # ratings + ratio tables
    python server/re/_rating_live.py lists      # da list fields (size + element ptrs)

Read-only.  `da` is the game's data manager; its per-keymode arrays are
`rvz: float[4]` (Standard) and `rwc: int[4]` (Basic), and its ratio tables are
`rwe: List<wc>` (`CATEGORY/COUNT/RATIO`) and `rwf: List<wd>` (`RATE/VALUE`).
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _mem  # noqa: E402

KM = ['4', '5', '6', '8']


def _res(cmd):
    r = _mem.send(cmd)
    return json.loads(r) if isinstance(r, str) else r


def read(addr, ln):
    r = _res({'op': 'readbytes', 'addr': hex(addr), 'len': str(ln)})
    return bytes.fromhex(r['hex'])


def u64(a):
    return struct.unpack('<Q', read(a, 8))[0]


def i32(a):
    return struct.unpack('<i', read(a, 4))[0]


def f32(a):
    return struct.unpack('<f', read(a, 4))[0]


def statics(cls='da'):
    r = _res({'op': 'zfstatics', 'cls': cls})
    return {f['name']: f for f in r['fields']}


def list_elems(ptr, maxn=64):
    items = u64(ptr + 0x10)
    size = i32(ptr + 0x18)
    n = min(size, maxn)
    return size, [u64(items + 0x20 + i * 8) for i in range(n)]


def ratings():
    st = statics('da')
    rvz = int(st['rvz']['ptr'], 16) + 0x20
    rwc = int(st['rwc']['ptr'], 16) + 0x20
    std = [round(struct.unpack_from('<f', read(rvz, 16), i)[0], 3) for i in (0, 4, 8, 12)]
    bas = [struct.unpack_from('<i', read(rwc, 16), i)[0] for i in (0, 4, 8, 12)]
    return std, bas, st


def ratio_tables(st):
    out = {}
    for name in ('rwe', 'rwf'):
        ptr = int(st[name]['ptr'], 16)
        size, elems = list_elems(ptr)
        rows = []
        for ep in elems:
            if name == 'rwe':       # wc: CATEGORY, COUNT, RATIO
                rows.append((i32(ep + 0x10), i32(ep + 0x14), round(f32(ep + 0x18), 4)))
            else:                   # wd: RATE, VALUE
                rows.append((i32(ep + 0x10), round(f32(ep + 0x14), 4)))
        out[name] = {'size': size, 'rows': rows}
    return out


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'ratings'
    std, bas, st = ratings()
    print('Standard [4,5,6,8]:', std)
    print('Basic    [4,5,6,8]:', bas)
    if mode == 'lists':
        for name, f in sorted(st.items()):
            t = f.get('type', '')
            if 'List' in t and f.get('ptr'):
                try:
                    size, elems = list_elems(int(f['ptr'], 16), 4)
                    print(f"  {name:6} {t[:48]:48} size={size} elems={[hex(e) for e in elems]}")
                except Exception as e:
                    print(f"  {name:6} {t[:48]} ERR {e}")
    if mode in ('ratings', 'tables'):
        tbl = ratio_tables(st)
        print('rwe (CATEGORY, COUNT, RATIO):', tbl['rwe']['size'])
        for row in tbl['rwe']['rows']:
            print('   ', row)
        print('rwf (RATE, VALUE):', tbl['rwf']['size'])
        for row in tbl['rwf']['rows']:
            print('   ', row)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
