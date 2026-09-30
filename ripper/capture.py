#!/usr/bin/env python3
"""ripper/capture.py — interactive, Frida-free chart capture.

Files every chart the running game fetches into
`extracted_charts/<song>/<keymode>/<difficulty>/`, with no Frida and no game
modification.  Play songs by hand; each one is captured as it loads.

What it starts
--------------
1. `server/re/_exp.py harvest`
   — forwards `login`/`pattern`/uncached-`cdn` upstream, so the official server
   mints a real session and real signed CloudFront URLs.
2. `server/re/_harvest_mem.py`
   — reads the client's live API session key straight out of process memory
   (no Frida), so the relay can decrypt the pattern request/response and label
   each capture.
3. `mitmdump -s server/re/_capture_addon.py`
   — the relay: serves the offline core, forwards the harvest endpoints, files
   each returned CDN body, decrypts it and derives `instrumentDic.json`.

Then just play songs.  Captures are printed as they land; Ctrl-C stops cleanly
and restores the server knobs it changed.

No server data?  Use `--passthrough`
-----------------------------------
The default `harvest` mode still needs a populated `server/data/` (the gameinfo/
myinfo templates the game reads between songs).  `--passthrough` forwards *every*
game-host request upstream instead, so nothing is served locally and capture
needs no server data at all — it is just a recording proxy.  The cost is that the
official account is used for the whole session, scores and progression included
(nothing stays private).  The memory harvester is still required, because
labelling a capture means decrypting the pattern request.

Capture needs an *unpatched* client
-----------------------------------
`harvest` forwards `c2s_login` to the official server, so the client must
encrypt its login block to the *official* RSA key.  The drop-in
`client/patcher/version.dll` rewrites that key to ours, and with it installed the
forwarded login cannot be decrypted upstream.  Use the built-in `version.dll`
(`client/patcher/install.sh uninstall`) for capture; leave the patcher for the
standalone offline server.  This script checks and refuses otherwise
(`--force` overrides).

Prerequisites
-------------
* The Wine prefix's proxy already points at this mitmdump (default
  `127.0.0.1:8080`) — the same setting every earlier capture used.
* Linux, for the memory harvester: allow ptrace with
  `sudo sysctl -w kernel.yama.ptrace_scope=0` (or run the harvester as root).
  Windows is same-user.

Usage
-----
    python3 ripper/capture.py                  # set up + relay + harvester + watch
    python3 ripper/capture.py --passthrough     # same, but forward EVERYTHING (no server data)
    python3 ripper/capture.py --setup-only      # only set the harvest knobs, then exit
    python3 ripper/capture.py --no-mitm         # the relay is already running elsewhere
    python3 ripper/capture.py --no-harvester    # the session key comes from elsewhere
    python3 ripper/capture.py --port 8080
    python3 ripper/capture.py --keep-knobs      # leave the harvest knobs in place on exit
"""
import argparse
import hashlib
import os
import re
import shutil
import signal
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, 'server')
GAME = os.path.join(ROOT, 'EZ2ON REBOOT R')
EXP = os.path.join(SERVER, 're', '_exp.py')
HARVESTER = os.path.join(SERVER, 're', '_harvest_mem.py')
ADDON = os.path.join(SERVER, 're', '_capture_addon.py')
LOG = os.path.join(SERVER, 'pserver.log')
ARCHIVE = os.path.join(ROOT, 'extracted_charts')

# lines from pserver.log worth echoing while a capture run is live
MARKERS = re.compile(r'CDN (OK|MISS|FAIL)|instrumentDic|NOT DECRYPTED|'
                     r'session key ->|key pair|unfiled')

_procs = []
_snap = None
_restore = True

# the experiment knobs _exp.py writes, snapshotted so capture can put them back
KNOBS = ('passthrough_endpoints.txt', 'mutate_urls.txt', 'mutate_bck.txt', 'chart_mode.txt')


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def live_version_kind():
    """'patcher' | 'gadget' | 'builtin' | 'unknown' for the game-dir version.dll."""
    live = os.path.join(GAME, 'version.dll')
    if not os.path.exists(live):
        return 'builtin'
    try:
        live_sha = sha256(live)
        for kind, p in (('patcher', os.path.join(ROOT, 'client', 'patcher', 'version.dll')),
                        ('gadget', os.path.join(GAME, 'version.dll.gadget'))):
            if os.path.exists(p) and sha256(p) == live_sha:
                return kind
    except OSError:
        pass
    return 'unknown'


def run_exp(*args):
    return subprocess.run([sys.executable, EXP, *args]).returncode


def find_mitmdump():
    cand = os.path.join(os.path.dirname(sys.executable), 'mitmdump')
    if os.path.exists(cand):
        return cand
    return shutil.which('mitmdump')


def spawn(argv, label):
    print('[capture] starting %s' % label)
    p = subprocess.Popen(argv)
    _procs.append(p)
    return p


def stop_all():
    for p in _procs:
        if p.poll() is None:
            p.terminate()
    deadline = time.time() + 5
    for p in _procs:
        try:
            p.wait(timeout=max(0.1, deadline - time.time()))
        except Exception:
            try:
                p.kill()
            except Exception:
                pass


def snapshot_knobs():
    snap = {}
    for n in KNOBS:
        p = os.path.join(SERVER, 'data', n)
        snap[n] = open(p).read() if os.path.exists(p) else None
    return snap


def restore_knobs(snap):
    if not snap:
        return
    for n, v in snap.items():
        p = os.path.join(SERVER, 'data', n)
        try:
            if v is None:
                if os.path.exists(p):
                    os.remove(p)
            else:
                os.makedirs(os.path.dirname(p), exist_ok=True)
                open(p, 'w').write(v)
        except OSError:
            pass


def _bye(*_a):
    stop_all()
    if _restore:
        restore_knobs(_snap)
    os._exit(0)


def follow(pos):
    """Echo new capture-relevant lines from server/pserver.log; return the new position."""
    if not os.path.exists(LOG):
        return pos
    try:
        with open(LOG, 'r', encoding='utf-8', errors='replace') as f:
            f.seek(pos)
            for line in f:
                if MARKERS.search(line):
                    print('   ' + line.rstrip())
                pos = f.tell()
    except OSError:
        pass
    return pos


def main():
    global _restore, _snap
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--port', type=int, default=8080,
                    help='mitmdump listen port (default 8080)')
    ap.add_argument('--setup-only', action='store_true',
                    help='write the harvest knobs and print what to run; do not start anything')
    ap.add_argument('--no-mitm', action='store_true',
                    help='do not start mitmdump (a capture relay is already running)')
    ap.add_argument('--no-harvester', action='store_true',
                    help='do not start the memory harvester (session key supplied elsewhere)')
    ap.add_argument('--passthrough', action='store_true',
                    help='forward EVERY request to the official servers (a pure recording '
                         'proxy): needs no server/data, but the official account is used '
                         'for the whole session (scores included)')
    ap.add_argument('--keep-knobs', action='store_true',
                    help='leave the harvest knobs in place on exit instead of restoring the '
                         'previous knobs')
    ap.add_argument('--force', action='store_true',
                    help='run even if the RSA-key patcher is installed (capture will then fail)')
    args = ap.parse_args()

    _restore = not args.keep_knobs
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(sig, _bye)
        except Exception:
            pass

    kind = live_version_kind()
    if kind == 'patcher' and not args.force:
        sys.exit(
            '[capture] the RSA-key patcher is installed as version.dll, but capture\n'
            '          forwards c2s_login upstream and needs the OFFICIAL public key.\n'
            '          Remove it first:  bash client/patcher/install.sh uninstall\n'
            '          (or pass --force to try anyway; login will fail upstream).')
    if kind == 'gadget':
        print('[capture] note: the Frida Gadget is installed.  It does not touch the\n'
              '          RSA key, so capture works, but the Gadget is what makes the\n'
              '          game unstable on launch.  Prefer the built-in version.dll.')

    mode = 'passthrough' if args.passthrough else 'harvest'
    if not args.passthrough and not os.path.exists(
            os.path.join(SERVER, 'data', 'gameinfo.json')):
        print('[capture] note: server/data/gameinfo.json is missing, so the offline core\n'
              '          has no music list to serve the game.  If you have not set up\n'
              '          server/data yet, pass --passthrough to forward everything to\n'
              '          the official servers instead (no server data needed).')
    _snap = snapshot_knobs()
    if args.passthrough:
        print('[capture] setting passthrough knobs (forward EVERYTHING upstream; '
              'no server data needed)')
    else:
        print('[capture] setting harvest knobs (forward login/pattern/cdn upstream)')
    if run_exp(mode) != 0:
        sys.exit('[capture] could not set the %s knobs' % mode)

    if args.setup_only:
        print('\n[capture] setup-only.  Run these yourself, then launch the game:\n'
              '    mitmdump -s %s\n'
              '    %s %s' % (os.path.relpath(ADDON, ROOT), sys.executable,
                            os.path.relpath(HARVESTER, ROOT)))
        print('[capture] Wine proxy must point at 127.0.0.1:%d' % args.port)
        _restore = False
        return

    os.makedirs(ARCHIVE, exist_ok=True)

    mitm = None
    if not args.no_mitm:
        mitmdump = find_mitmdump()
        if not mitmdump:
            sys.exit('[capture] mitmdump not found on PATH or next to the interpreter; '
                     'install mitmproxy or pass --no-mitm')
        mitm = spawn([mitmdump, '-s', ADDON, '--listen-port', str(args.port)],
                     'mitmdump (relay) on 127.0.0.1:%d' % args.port)
    else:
        print('[capture] not starting mitmdump (--no-mitm)')

    harv = None
    if not args.no_harvester:
        harv = spawn([sys.executable, HARVESTER], 'the memory harvester')

    print('\n[capture] ready.  Point the Wine proxy at 127.0.0.1:%d, launch the game,'
          % args.port)
    print('[capture] then play songs.  Captures land under %s/'
          % os.path.relpath(ARCHIVE, ROOT))
    print('[capture] Ctrl-C to stop.\n')

    pos = os.path.getsize(LOG) if os.path.exists(LOG) else 0
    try:
        while True:
            pos = follow(pos)
            if mitm is not None and mitm.poll() is not None:
                print('[capture] mitmdump exited (code %s); stopping' % mitm.returncode)
                break
            if harv is not None and harv.poll() is not None:
                print('[capture] the memory harvester exited (code %s); stopping'
                      % harv.returncode)
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        print('\n[capture] stopped')
    finally:
        stop_all()
        if _restore:
            print('[capture] restoring the previous server knobs')
            restore_knobs(_snap)


if __name__ == '__main__':
    main()
