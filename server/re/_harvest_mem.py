#!/usr/bin/env python3
"""Frida-free session-key harvester.

The client serialises a small JSON

    {...,"version":"2026.09.04.001","key":"<32 uppercase hex>","iv":"<16 uppercase hex>"}

while building the login request, and keeps it in memory at least across that
exchange.  Scanning the game's writable memory for `"key":"...","iv":"..."`
yields the live API session key directly — no Frida, no RSA swap, no client
modification, no official server.

`_pserver.py` waits for `server/session_key.json` in `ensure_key()`, so login
is held until this harvester has found the key.  That makes the race
deterministic even though the JSON is transient.

Lifecycle rules (learned the hard way):
  * the key JSON is freed once login completes, so a valid key must survive
    the JSON disappearing from memory — never clear a key just because a rescan
    finds nothing;
  * clear the key only when the game process itself is gone (a relaunch), so
    `ensure_key()` waits for the *new* session's key instead of serving the old
    one (which makes the client NRE its login);
  * a crash-handler child also maps the game image, so filter to EZ2ON.exe.

Cross-platform via `client/ez2on_patch.py` backends.  On Linux needs
ptrace_scope to allow it (sudo, or `kernel.yama.ptrace_scope=0`); Windows is
same-user.

    python server/re/_harvest_mem.py [--interval 0.5] [--once]
"""
import argparse
import json
import os
import re
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # repo root
sys.path.insert(0, os.path.join(ROOT, 'client'))
import ez2on_patch as ep  # noqa: E402

OUT = os.path.join(ROOT, 'server', 'session_key.json')
PAT = re.compile(rb'"key":"([0-9A-F]{32})","iv":"([0-9A-F]{16})"')


def log(*a):
    print(f'[{time.strftime("%H:%M:%S")}] ', *a, flush=True)


def make_backend(pid):
    return ep.windows_backend(pid) if sys.platform == 'win32' else ep.LinuxProc(pid)


def pid_alive(pid):
    if pid is None:
        return False
    if sys.platform == 'win32':
        import ctypes
        k32 = ctypes.WinDLL('kernel32', use_last_error=True)
        h = k32.OpenProcess(0x1000, False, pid)   # PROCESS_QUERY_LIMITED_INFORMATION
        if h:
            k32.CloseHandle(h)
            return True
        return False
    return os.path.exists(f'/proc/{pid}')


def game_pids():
    """Live EZ2ON.exe processes (exclude the crash handler)."""
    if sys.platform == 'win32':
        return ep.windows_find_pids()
    out = []
    for name in os.listdir('/proc'):
        if not name.isdigit():
            continue
        try:
            comm = open(f'/proc/{name}/comm').read().strip()
        except OSError:
            continue
        if comm == 'EZ2ON.exe':
            out.append(int(name))
    return out


def scan_for_key(be):
    for start, end, perms, _path in be.regions():
        if 'w' not in perms:
            continue
        pos = start
        while pos < end:
            data = be.read(pos, min(ep.CHUNK, end - pos))
            if not data:
                break
            m = PAT.search(data)
            if m:
                return m.group(1).decode(), m.group(2).decode(), pos + m.start()
            pos += len(data)
    return None


def read_at(be, addr):
    if addr is None:
        return None
    m = PAT.search(be.read(addr, 200) or b'')
    return (m.group(1).decode(), m.group(2).decode()) if m else None


def clear_key(reason):
    removed = False
    for p in (OUT, OUT + '.tmp'):
        try:
            if os.path.exists(p):
                os.remove(p)
                removed = True
        except Exception:
            pass
    if removed:
        log(f'cleared stale key ({reason})')


def write_key(key, iv):
    try:
        old = json.load(open(OUT))
        if old.get('aes_key') == key and old.get('aes_iv') == iv:
            return False
    except Exception:
        pass
    tmp = OUT + '.tmp'
    json.dump({'aes_key': key, 'aes_iv': iv, 'source': 'mem',
               't': time.time()}, open(tmp, 'w'))
    os.replace(tmp, OUT)
    log(f'session key -> {OUT}: {key} / {iv}')
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--interval', type=float, default=0.5)
    ap.add_argument('--rescan', type=float, default=2.0,
                    help='seconds between full re-scans when the cached address is cold')
    ap.add_argument('--once', action='store_true')
    args = ap.parse_args()

    if os.path.exists(OUT):
        os.remove(OUT)
    be = pid = addr = None
    last_scan = 0.0
    while True:
        # a game process we had been reading is gone -> its session ended, so
        # drop the key and let _pserver.py wait for the next session's key
        if pid is not None and not pid_alive(pid):
            log(f'game pid {pid} exited; re-finding the game')
            clear_key('game exited')
            try:
                be.close()
            except Exception:
                pass
            be = pid = addr = None
            last_scan = 0.0

        if be is None:
            for cand in game_pids():
                try:
                    be = make_backend(cand)
                    pid = cand
                    addr = None
                    last_scan = 0.0
                    log(f'attached to pid {pid}; scanning for the key JSON')
                    break
                except Exception as e:
                    log(f'cannot open pid {cand}: {e}')
                    be = None
            if be is None and args.once:
                log('no game process found')
                return 1

        if be is not None:
            try:
                hit = read_at(be, addr)
                if hit is None and (time.time() - last_scan) >= args.rescan:
                    last_scan = time.time()
                    found = scan_for_key(be)
                    if found:
                        addr = found[2]
                        hit = (found[0], found[1])
                if hit:
                    write_key(hit[0], hit[1])
                    if args.once:
                        return 0
            except Exception as e:
                log(f'read failed ({e}); re-finding the game')
                try:
                    be.close()
                except Exception:
                    pass
                be = pid = addr = None
                last_scan = 0.0
                time.sleep(1.0)
                continue

        time.sleep(args.interval)


if __name__ == '__main__':
    raise SystemExit(main())
