#!/usr/bin/env python3
"""EZ2ON REBOOT:R — swap the live `zf.publicKey` in the running game (no Frida).

Why: the client generates its API session key/IV locally and never sends them
except RSA-wrapped in `c2s_login.data`, encrypted under a public key baked into
the build.  The private server owns a keypair; this tool rewrites the client's
`<RSAKeyValue>` string so the login block is encrypted to the server's public
key, which the server then decrypts (`server/_rsa.py`) to recover the session
key.  That removes the Frida harvester from the loop.

How: find the game process, locate the UTF-16 (or UTF-8) `<RSAKeyValue>` string
in its writable memory, and overwrite its `<Modulus>`/`<Exponent>` values in
place with ours — same byte length, so no reallocation or pointer surgery.  No
hooks, no code patches, no Interceptor; plain memory reads/writes.

Backends:
  * Linux / Proton  — /proc/<pid>/maps + /proc/<pid>/mem   (works today)
  * Windows         — VirtualQueryEx + Read/WriteProcessMemory (ctypes)

Usage:
    python client/ez2on_patch.py --scan           # report publicKey hits
    python client/ez2on_patch.py --patch          # swap it for the server key
    python client/ez2on_patch.py --patch --watch  # keep watching (re)launches
    python client/ez2on_patch.py --patch --pid 12345

The public key is read from server/data/server_rsa_public.xml (generate with
`python server/_rsa.py init`), or from --pub.
"""
import argparse
import base64
import os
import re
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_PUB = os.path.join(ROOT, 'server', 'data', 'server_rsa_public.xml')
MARKERS = {
    'utf-16le': '<RSAKeyValue>'.encode('utf-16-le'),
    'ascii': '<RSAKeyValue>'.encode('ascii'),
}
CLOSE = {
    'utf-16le': '</RSAKeyValue>'.encode('utf-16-le'),
    'ascii': '</RSAKeyValue>'.encode('ascii'),
}
CHUNK = 8 * 1024 * 1024


def log(*a):
    print(f'[{time.strftime("%H:%M:%S")}] ', *a, flush=True)


def decompose(xml, enc: str):
    """Split an <RSAKeyValue> blob into (prefix, modulus, mid, exponent, suffix)
    so only the two values need replacing.  Accepts bytes or str."""
    s = xml.decode(enc) if isinstance(xml, (bytes, bytearray)) else xml
    m = re.match(r'^(.*?<Modulus>)(.*?)(</Modulus>.*?<Exponent>)(.*?)(</Exponent>.*)$',
                 s, re.S)
    if not m:
        raise ValueError('not an <RSAKeyValue>')
    return m.groups()


def server_key_values(pub_path):
    xml = open(pub_path, encoding='utf-8').read().strip()
    _, mod, _, exp, _ = decompose(xml, 'utf-8')
    return mod, exp


# --------------------------------------------------------------------------
# Linux / Proton backend
# --------------------------------------------------------------------------
class LinuxProc:
    def __init__(self, pid):
        self.pid = pid
        self.f = open(f'/proc/{pid}/mem', 'rb+', buffering=0)

    def regions(self):
        out = []
        try:
            for line in open(f'/proc/{self.pid}/maps'):
                parts = line.split()
                a, b = parts[0].split('-')
                perms = parts[1]
                path = parts[-1] if len(parts) >= 6 else ''
                out.append((int(a, 16), int(b, 16), perms, path))
        except FileNotFoundError:
            pass
        return out

    def read(self, addr, n):
        try:
            return os.pread(self.f.fileno(), n, addr)
        except OSError:
            return b''

    def write(self, addr, data):
        return os.pwrite(self.f.fileno(), data, addr)

    def close(self):
        self.f.close()


def find_game_pids_linux():
    """Processes whose maps mention GameAssembly.dll (Wine/Proton game)."""
    pids = []
    for name in os.listdir('/proc'):
        if not name.isdigit():
            continue
        try:
            maps = open(f'/proc/{name}/maps').read()
        except OSError:
            continue
        if 'GameAssembly.dll' in maps or 'EZ2ON' in maps:
            pids.append(int(name))
    return pids


# --------------------------------------------------------------------------
# Windows backend (ctypes)
# --------------------------------------------------------------------------
def windows_backend(pid):
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL('kernel32', use_last_error=True)
    psapi = ctypes.WinDLL('psapi', use_last_error=True)

    PROCESS_VM_READ = 0x0010
    PROCESS_VM_WRITE = 0x0020
    PROCESS_VM_OPERATION = 0x0008
    PROCESS_QUERY_INFORMATION = 0x0400
    MEM_COMMIT = 0x1000
    PAGE_GUARD = 0x100
    PAGE_NOACCESS = 0x01
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_WRITECOPY = 0x08
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80

    class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
        _fields_ = [('BaseAddress', ctypes.c_ulonglong),
                    ('AllocationBase', ctypes.c_ulonglong),
                    ('AllocationProtect', wintypes.DWORD),
                    ('__alignment1', wintypes.DWORD),
                    ('RegionSize', ctypes.c_ulonglong),
                    ('State', wintypes.DWORD),
                    ('Protect', wintypes.DWORD),
                    ('Type', wintypes.DWORD),
                    ('__alignment2', wintypes.DWORD)]

    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE |
                        PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                        False, pid)
    if not h:
        raise OSError(f'OpenProcess({pid}) failed: {ctypes.get_last_error()}')

    read_prot = {PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
                 PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
                 PAGE_EXECUTE_WRITECOPY}
    write_prot = {PAGE_READWRITE, PAGE_WRITECOPY,
                  PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY}

    class Backend:
        def regions(self):
            out = []
            addr = 0
            mbi = MEMORY_BASIC_INFORMATION64()
            while k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi),
                                     ctypes.sizeof(mbi)):
                size = mbi.RegionSize
                prot = mbi.Protect
                perms = ''
                if mbi.State == MEM_COMMIT and not (prot & PAGE_GUARD):
                    if prot & PAGE_NOACCESS == 0:
                        perms += 'r' if prot in read_prot else '-'
                        perms += 'w' if prot in write_prot else '-'
                out.append((mbi.BaseAddress, mbi.BaseAddress + size, perms, ''))
                addr = mbi.BaseAddress + size
            return out

        def read(self, address, n):
            buf = ctypes.create_string_buffer(n)
            got = ctypes.c_size_t(0)
            if not k32.ReadProcessMemory(h, ctypes.c_void_p(address), buf, n,
                                         ctypes.byref(got)):
                return b''
            return buf.raw[:got.value]

        def write(self, address, data):
            got = ctypes.c_size_t(0)
            ok = k32.WriteProcessMemory(h, ctypes.c_void_p(address), data,
                                        len(data), ctypes.byref(got))
            return got.value if ok else 0

        def close(self):
            pass

    return Backend()


def windows_find_pids():
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL('kernel32', use_last_error=True)
    psapi = ctypes.WinDLL('psapi', use_last_error=True)
    arr = (wintypes.DWORD * 4096)()
    needed = wintypes.DWORD()
    if not psapi.EnumProcesses(ctypes.byref(arr), ctypes.sizeof(arr),
                               ctypes.byref(needed)):
        return []
    n = needed.value // ctypes.sizeof(wintypes.DWORD)
    out = []
    for pid in list(arr[:n]):
        hh = k32.OpenProcess(0x0400 | 0x0010, False, pid)
        if not hh:
            continue
        buf = ctypes.create_unicode_buffer(260)
        k32.QueryFullProcessImageNameW(hh, 0, buf,
                                       ctypes.byref(wintypes.DWORD(260)))
        k32.CloseHandle(hh)
        if buf.value.lower().endswith('ez2on.exe'):
            out.append(pid)
    return out


# --------------------------------------------------------------------------
# scanning / patching
# --------------------------------------------------------------------------
def scan_marker(be, marker, writable_only=False):
    """Yield (addr, region_perms) for each marker occurrence."""
    needle = marker
    ov = len(needle) - 1
    for start, end, perms, _path in be.regions():
        if 'r' not in perms:
            continue
        if writable_only and 'w' not in perms:
            continue
        pos = start
        tail = b''
        while pos < end:
            n = min(CHUNK, end - pos)
            data = be.read(pos, n)
            if not data:
                break
            buf = tail + data
            base = pos - len(tail)
            i = buf.find(needle)
            while i != -1:
                yield base + i, perms
                i = buf.find(needle, i + 1)
            tail = buf[-(ov):] if ov else b''
            pos += len(data)
            if len(data) < n:
                break


def extract_xml(be, addr, enc, limit=2048):
    data = be.read(addr, limit)
    close = CLOSE[enc]
    j = data.find(close)
    if j == -1:
        return None
    xml = data[:j + len(close)]
    # reject a marker whose "close" belongs to an unrelated string: a real
    # publicKey carries both tags within a few hundred bytes
    if enc == 'ascii' and (b'<Modulus>' not in xml or b'<Exponent>' not in xml):
        return None
    return xml


def find_one(be, verbose=True, writable_only=False):
    """Return a list of usable hits: dict(addr, enc, xml, perms, writable)."""
    hits = []
    for enc, marker in MARKERS.items():
        for addr, perms in scan_marker(be, marker, writable_only=writable_only):
            xml = extract_xml(be, addr, enc)
            if xml is None:
                continue
            hits.append({'addr': addr, 'enc': enc, 'xml': xml, 'perms': perms,
                         'writable': 'w' in perms})
            if verbose:
                log(f'  hit @ {addr:#x} [{enc}] perms={perms} len={len(xml)}')
    return hits


ORIG_FILE = os.path.join(ROOT, 'server', 'data', 'orig_modulus.hex')


def load_orig_raw():
    """The client build's original RSA modulus (raw 256 B), if we have it.

    Knowing it lets us patch the cached provider modulus in a *single* pass
    without first finding the <RSAKeyValue> literal — which is what makes the
    patch land before the login block is built.  Extract it once with
    `client/ez2on_patch.py --dump-orig` (or from any full memory scan).
    """
    try:
        h = open(ORIG_FILE).read().strip()
        if len(h) == 512:
            return bytes.fromhex(h)
    except Exception:
        pass
    return None


def patch_xml_at(be, addr, enc, mod, exp, dry=False):
    """Rewrite one <RSAKeyValue> blob's modulus/exponent in place."""
    xml = extract_xml(be, addr, enc)
    if xml is None:
        return 0
    try:
        pre, old_mod, mid, old_exp, suf = decompose(xml, enc)
    except ValueError:
        return 0
    if old_mod == mod:
        return 0
    if len(old_mod) != len(mod) or len(old_exp) != len(exp):
        return 0
    new = (pre + mod + mid + exp + suf).encode(enc)
    if len(new) != len(xml):
        return 0
    if dry:
        log(f'  @ {addr:#x} [{enc}] would swap {old_mod[:12]}… -> {mod[:12]}…')
        return 1
    got = be.write(addr, new)
    if got == len(new):
        log(f'  @ {addr:#x} [{enc}] PATCHED {old_mod[:12]}… -> {mod[:12]}…')
        return 1
    log(f'  @ {addr:#x} [{enc}] write short ({got}/{len(new)})')
    return 0


def do_patch(be, pub_path, dry=False):
    """One fast pass: patch the cached raw modulus and both key strings.

    The order inside a pass matters for latency, not correctness: the raw
    modulus is what the (already-built) provider encrypts with, so patching it
    is the time-critical part; the literal/string are for any later rebuild.
    """
    mod, exp = server_key_values(pub_path)
    our_raw = base64.b64decode(mod)
    orig_raw = load_orig_raw()
    n_raw = n_str = 0
    for start, end, perms, path in be.regions():
        if 'w' not in perms:
            continue
        pos = start
        while pos < end:
            data = be.read(pos, min(CHUNK, end - pos))
            if not data:
                break
            if orig_raw and orig_raw != our_raw:
                i = data.find(orig_raw)
                while i != -1:
                    if dry:
                        log(f'  raw @ {pos + i:#x} would swap')
                    else:
                        be.write(pos + i, our_raw)
                        log(f'  raw @ {pos + i:#x} PATCHED ({path or "anon"})')
                    n_raw += 1
                    i = data.find(orig_raw, i + 1)
            for enc, marker in MARKERS.items():
                i = data.find(marker)
                while i != -1:
                    n_str += patch_xml_at(be, pos + i, enc, mod, exp, dry)
                    i = data.find(marker, i + 1)
            pos += len(data)
    if n_raw:
        log(f'  raw modulus copies patched: {n_raw}')
    return n_raw + n_str

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--pub', default=DEFAULT_PUB)
    ap.add_argument('--pid', type=int)
    ap.add_argument('--scan', action='store_true')
    ap.add_argument('--patch', action='store_true')
    ap.add_argument('--watch', action='store_true',
                    help='keep watching for the string (patch as soon as it exists)')
    ap.add_argument('--interval', type=float, default=0.25)
    ap.add_argument('--timeout', type=float, default=0, help='stop after N seconds')
    args = ap.parse_args()

    if not os.path.exists(args.pub):
        sys.exit(f'no public key at {args.pub}; run: python server/_rsa.py init')

    if sys.platform == 'win32':
        backend_cls = windows_backend
        find_pids = windows_find_pids
    else:
        backend_cls = LinuxProc
        find_pids = find_game_pids_linux

    t0 = time.time()
    while True:
        pid = args.pid
        if not pid:
            pids = find_pids()
            pid = pids[0] if pids else None
        if pid:
            try:
                be = backend_cls(pid)
            except Exception as e:
                be = None
                log(f'cannot open pid {pid}: {e}')
            if be:
                try:
                    if args.scan or not args.patch:
                        hits = find_one(be)
                        log(f'{pid}: {len(hits)} publicKey hit(s)')
                    else:
                        n = do_patch(be, args.pub)
                        if n:
                            log(f'{pid}: patched {n} copy/copies')
                            if not args.watch:
                                return
                        elif not args.watch:
                            log(f'{pid}: nothing to patch')
                finally:
                    be.close()
        elif not args.watch:
            log('no EZ2ON process found — launch the game, then rerun; or use --watch')
        if not args.watch:
            return
        if args.timeout and time.time() - t0 > args.timeout:
            log('timeout')
            return
        time.sleep(args.interval)


if __name__ == '__main__':
    main()
