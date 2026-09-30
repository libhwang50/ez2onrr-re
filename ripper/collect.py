#!/usr/bin/env python3
"""ripper/collect.py — official-server request collector for testers.

A passive recording proxy: every game-host request is forwarded to the
**official** server and the request, the response, and the API session key that
was live at the time are written to a self-contained bundle.  Nothing is served
locally, the private server is not involved, and the client is not modified —
this collects the official server's answers only.  Decrypt a submission later
with `ripper/collect_read.py`.

Use it for anything the private server cannot produce, e.g. the per-account DLC
ownership the official `c2s_login` returns (`apps[].ownsapp`, `member.DLC`) or
any other endpoint a tester's own account can reach.

What it starts
--------------
1. `server/re/_harvest_mem.py` — the session key, read from process memory
   (no Frida), so the encrypted bodies can be decrypted offline.
2. `mitmdump -s ripper/_collect_addon.py` — the recording proxy.

Then a tester points the Wine proxy at this mitmdump, launches the game, signs
in, and drives the screens to record.  Ctrl-C stops and packages the bundle.

Capture needs an *unpatched* client
-----------------------------------
The login must be encrypted to the **official** RSA key, so the drop-in
`client/patcher/version.dll` (which swaps that key for ours) has to go:
`bash client/patcher/install.sh uninstall`.  This script checks and refuses
otherwise (`--force` overrides, but login will fail upstream).

Prerequisites
-------------
* The Wine prefix's proxy points at this mitmdump (default `127.0.0.1:8080`) and
  trusts the mitmproxy CA — the same setting every capture uses.
* Linux, for the memory harvester: allow ptrace with
  `sudo sysctl -w kernel.yama.ptrace_scope=0` (or run the harvester as root).
  Windows is same-user.

Usage
-----
    python3 ripper/collect.py                  # record + zip on exit
    python3 ripper/collect.py --cdn-body       # also keep CDN bodies (large)
    python3 ripper/collect.py --max-body 2M    # cap any recorded body
    python3 ripper/collect.py --no-harvester   # session key supplied elsewhere
    python3 ripper/collect.py --no-mitm        # a proxy is already running
    python3 ripper/collect.py --out /tmp/run   # explicit bundle directory
"""
import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import capture  # noqa: E402  (live_version_kind / find_mitmdump)

ADDON = os.path.join(HERE, '_collect_addon.py')
HARVESTER = os.path.join(ROOT, 'server', 're', '_harvest_mem.py')
COLLECTED = os.path.join(ROOT, 'collected')

OFFICIAL_HOSTS = ('game1-play.ez2game.co.kr',
                  'game1-rank.ez2game.co.kr',
                  'game1-cdn.ez2game.co.kr')

_procs = []
_bundle = None
_finalized = False
_no_zip = False


def parse_size(s):
    s = str(s).strip().lower()
    if not s or s == '0':
        return 0
    mult = 1
    if s[-1] in 'kmg':
        mult = {'k': 1024, 'm': 1024 ** 2, 'g': 1024 ** 3}[s[-1]]
        s = s[:-1]
    return int(float(s) * mult)


def spawn(argv, label, env=None):
    print('[collect] starting %s' % label)
    p = subprocess.Popen(argv, env=env)
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


def write_meta(bundle, extra):
    p = os.path.join(bundle, 'meta.json')
    meta = {}
    if os.path.exists(p):
        try:
            meta = json.load(open(p))
        except Exception:
            meta = {}
    meta.update(extra)
    with open(p, 'w') as f:
        json.dump(meta, f, indent=1, ensure_ascii=False)


def count_flows(bundle):
    p = os.path.join(bundle, 'flows.jsonl')
    if not os.path.exists(p):
        return 0
    with open(p) as f:
        return sum(1 for _ in f)


def summarize(bundle):
    """Per-endpoint counts, so a tester can see what they recorded."""
    p = os.path.join(bundle, 'flows.jsonl')
    counts = {}
    if os.path.exists(p):
        with open(p) as f:
            for line in f:
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                if r.get('host') == 'game1-cdn.ez2game.co.kr':
                    ep = 'cdn'
                else:
                    ep = (r.get('path') or '').split('?')[0].rstrip('/').split('/')[-1]
                    ep = ep or r.get('host', '?')
                counts[ep] = counts.get(ep, 0) + 1
    return counts


def finalize():
    global _finalized
    if _finalized:
        return
    _finalized = True
    stop_all()
    if not _bundle:
        return
    n = count_flows(_bundle)
    write_meta(_bundle, {'ended': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'flows': n})
    counts = summarize(_bundle)
    print('[collect] %d flow(s) recorded in %s' % (n, _bundle))
    if counts:
        print('[collect] by endpoint: ' + ', '.join(
            '%s×%d' % (k, v) for k, v in sorted(counts.items(), key=lambda kv: -kv[1])))
    if not n:
        print('[collect] nothing was recorded — did the game actually reach the '
              'official server?  (patcher uninstalled? proxy pointed here?)')
    if _no_zip:
        print('[collect] send that directory to the maintainer.')
        return
    try:
        z = shutil.make_archive(_bundle.rstrip('/\\'), 'zip', _bundle)
        print('[collect] submission bundle: %s' % z)
        print('[collect] send that zip to the maintainer.')
    except Exception as e:
        print('[collect] could not zip (%s); send the directory instead' % e)


def _bye(*_a):
    finalize()
    os._exit(0)


def main():
    global _bundle, _no_zip
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--port', type=int, default=8080,
                    help='mitmdump listen port (default 8080)')
    ap.add_argument('--out', help='bundle directory (default collected/<timestamp>/)')
    ap.add_argument('--no-mitm', action='store_true',
                    help='do not start mitmdump (a proxy is already running)')
    ap.add_argument('--no-harvester', action='store_true',
                    help='do not start the memory harvester (session key supplied elsewhere)')
    ap.add_argument('--cdn-body', action='store_true',
                    help='also record CDN bodies (charts/keysounds — large)')
    ap.add_argument('--max-body', type=parse_size, default=0,
                    help='cap the size of any recorded body, e.g. 2M (default 0 = unlimited)')
    ap.add_argument('--no-zip', action='store_true',
                    help='do not zip the bundle on exit')
    ap.add_argument('--force', action='store_true',
                    help='run even if the RSA-key patcher is installed (login will fail)')
    args = ap.parse_args()
    _no_zip = args.no_zip

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(sig, _bye)
        except Exception:
            pass

    kind = capture.live_version_kind()
    if kind == 'patcher' and not args.force:
        sys.exit(
            '[collect] the RSA-key patcher is installed as version.dll, but the\n'
            '          collector forwards the login to the OFFICIAL server and needs\n'
            '          the OFFICIAL public key.  Remove it first:\n'
            '            bash client/patcher/install.sh uninstall\n'
            '          (or pass --force to try anyway; login will fail upstream).')
    if kind == 'gadget':
        print('[collect] note: the Frida Gadget is installed.  It does not touch the\n'
              '          RSA key, so collecting works, but the Gadget makes the game\n'
              '          unstable on launch.  Prefer the built-in version.dll.')

    if args.out:
        _bundle = os.path.abspath(args.out)
    else:
        _bundle = os.path.join(COLLECTED, time.strftime('%Y%m%d-%H%M%S'))
    os.makedirs(_bundle, exist_ok=True)

    env = dict(os.environ)
    env['EZ2_COLLECT_DIR'] = _bundle
    env['EZ2_COLLECT_HOSTS'] = ','.join(OFFICIAL_HOSTS)
    env['EZ2_COLLECT_CDN'] = '1' if args.cdn_body else '0'
    env['EZ2_COLLECT_MAX'] = str(args.max_body)
    env['EZ2_SESSION_KEY'] = os.path.join(ROOT, 'server', 'session_key.json')

    write_meta(_bundle, {
        'tool': 'ripper/collect.py',
        'started': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        'host': socket.gethostname(),
        'port': args.port,
        'patcher': kind,
        'official_hosts': list(OFFICIAL_HOSTS),
        'cdn_body': bool(args.cdn_body),
        'max_body': args.max_body,
    })

    print('[collect] official-server bundle: %s' % _bundle)

    mitm = None
    if not args.no_mitm:
        mitmdump = capture.find_mitmdump()
        if not mitmdump:
            sys.exit('[collect] mitmdump not found on PATH or next to the interpreter; '
                     'install mitmproxy or pass --no-mitm')
        mitm = spawn([mitmdump, '-s', ADDON, '--listen-port', str(args.port)],
                     'mitmdump (official-only collector) on 127.0.0.1:%d' % args.port,
                     env=env)
    else:
        print('[collect] not starting mitmdump (--no-mitm)')

    harv = None
    if not args.no_harvester:
        harv = spawn([sys.executable, HARVESTER], 'the memory harvester', env=env)

    print('\n[collect] ready.  Point the Wine proxy at 127.0.0.1:%d,' % args.port)
    print('[collect] launch the game, and sign in with the account to collect.')
    print('[collect] Drive the game through the screens you want recorded, then Ctrl-C.\n')

    try:
        while True:
            if mitm is not None and mitm.poll() is not None:
                print('[collect] mitmdump exited (code %s); stopping' % mitm.returncode)
                break
            if harv is not None and harv.poll() is not None:
                print('[collect] the memory harvester exited (code %s); stopping'
                      % harv.returncode)
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        print('\n[collect] stopped')
    finally:
        finalize()


if __name__ == '__main__':
    main()
