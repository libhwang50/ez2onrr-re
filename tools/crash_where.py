#!/usr/bin/env python3
"""Summarise the game's Unity crash dumps: exception code + faulting module.

The client writes Windows minidumps under the Proton prefix at
`.../AppData/Local/Temp/Neonovice/EZ2ON/Crashes/Crash_<ts>/crash.dmp`.  This
reads the MINIDUMP header/streams directly (no debugger, no Wine) and prints,
for each dump, the exception code, the faulting address and the module it falls
in — enough to tell *our* injected `version.dll` apart from the game's own
chronic crashes (`ucrtbase.dll`, or an unmapped JIT address).

    python3 tools/crash_where.py                 # the default prefix, all dumps
    python3 tools/crash_where.py --last 20       # only the newest N
    python3 tools/crash_where.py path/to/crash.dmp
    python3 tools/crash_where.py --prefix /other/pfx

What it found on 2026-09-24: the old in-place `version.dll` memory scan faulted
at `VERSION.dll+0x194d` (`cmpb $0x3c,(%rbx)` — a region unmapped between the
`VirtualQuery` and the read).  The fix is snapshot reads via `ReadProcessMemory`
in `client/patcher/ez2on_version_proxy.c`.
"""
import argparse
import glob
import os
import struct
import sys

DEFAULT_PREFIX = os.path.expanduser(
    '~/.local/share/Steam/steamapps/compatdata/1477590/pfx')
CRASH_SUBDIR = ('drive_c/users/steamuser/AppData/Local/Temp/'
                'Neonovice/EZ2ON/Crashes')

# MINIDUMP stream types we care about
EXCEPTION, MODULE_LIST = 6, 4
# MINIDUMP_MODULE is 108 bytes; BaseOfImage@0, SizeOfImage@8, ModuleNameRva@20
MODULE_SIZE = 108


def parse(path):
    d = open(path, 'rb').read()
    if d[:4] != b'MDMP':
        return None
    n_streams, dir_rva = struct.unpack_from('<II', d, 8)
    streams = {}
    for i in range(n_streams):
        stype, _size, rva = struct.unpack_from('<III', d, dir_rva + 12 * i)
        streams.setdefault(stype, rva)
    out = {'code': None, 'addr': None, 'modules': []}

    if EXCEPTION in streams:
        r = streams[EXCEPTION]
        code, _flags = struct.unpack_from('<II', d, r + 8)
        addr, = struct.unpack_from('<Q', d, r + 24)
        out['code'], out['addr'] = code, addr

    if MODULE_LIST in streams:
        r = streams[MODULE_LIST]
        count, = struct.unpack_from('<I', d, r)
        for i in range(count):
            m = r + 4 + MODULE_SIZE * i
            base, size = struct.unpack_from('<QI', d, m)
            name_rva, = struct.unpack_from('<I', d, m + 20)
            ln, = struct.unpack_from('<I', d, name_rva)
            name = d[name_rva + 4:name_rva + 4 + ln].decode('utf-16-le', 'replace')
            out['modules'].append((base, size, os.path.basename(name)))
    return out


def owner(addr, modules):
    if addr is None:
        return '?'
    for base, size, name in modules:
        if base <= addr < base + size:
            return f'{name}+0x{addr - base:x}'
    return f'UNMAPPED 0x{addr:x}'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('paths', nargs='*', help='crash.dmp files')
    ap.add_argument('--prefix', default=DEFAULT_PREFIX)
    ap.add_argument('--last', type=int, default=0)
    args = ap.parse_args()

    files = args.paths
    if not files:
        files = sorted(glob.glob(os.path.join(args.prefix, CRASH_SUBDIR, 'Crash_*', 'crash.dmp')))
        if args.last:
            files = files[-args.last:]
    if not files:
        sys.exit('no crash dumps found')

    counts = {}
    for f in files:
        p = parse(f)
        stamp = os.path.basename(os.path.dirname(f))
        if p is None:
            print(f'{stamp}: not a minidump')
            continue
        where = owner(p['addr'], p['modules'])
        counts[where.split('+')[0]] = counts.get(where.split('+')[0], 0) + 1
        print(f'{stamp}: code=0x{p["code"] or 0:08x} -> {where}')
    print('\nby faulting module:')
    for name, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f'  {n:4d}  {name}')


if __name__ == '__main__':
    main()
