"""Frida session-key bridge for the private server.

Polls zf.aes_key / zf.aes_iv (the API session key the client generates at
login — zf.gnf: RNGCryptoServiceProvider -> hex, AGENTS.md §3.1) at 1 Hz
through the Gadget and writes every change to server/session_key.json, which
server/_pserver.py reads per request.

Auto-reattaches when the game restarts: without this the server keeps
encrypting under a stale key and the client silently falls back to the
official servers (or fails).

Run while playing:
    .venv/bin/python server/_harvest_session.py

Exits cleanly on Ctrl-C (detaches — see tools/README.md).
"""
import json
import os
import signal
import sys
import time

import frida

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'server', 'session_key.json')
DRIVER = os.path.join(ROOT, 'tools', 'build', '_sesskey_run.js')

_running = True
_fail_host = '127.0.0.1:27042'


def _stop(_sig, _frm):
    global _running
    _running = False


def write_key(key, iv):
    tmp = OUT + '.tmp'
    json.dump({'aes_key': key, 'aes_iv': iv, 't': time.time()},
              open(tmp, 'w'))
    os.replace(tmp, OUT)
    print(f'[{time.strftime("%H:%M:%S")}] session key -> {OUT}: {key} / {iv}')


def attach():
    """Attach to the Gadget and load the read driver. Returns (session, script)."""
    src = open(DRIVER).read()
    dev = frida.get_device_manager().add_remote_device(_fail_host)
    session = dev.attach('Gadget')
    script = session.create_script(src)
    script.load()
    return session, script


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGHUP, _stop)

    # a fresh harvester run means a fresh game session — drop any stale key so
    # the server never encrypts the login response under the previous session
    if os.path.exists(OUT):
        os.remove(OUT)
        print('removed stale session_key.json')

    session = script = None
    last = None
    misses = 0
    reattaches = 0
    while _running:
        time.sleep(1.0)
        try:
            if script is None:
                session, script = attach()
                print(f'[{time.strftime("%H:%M:%S")}] attached to Gadget; '
                      'polling zf.aes_key/aes_iv at 1 Hz')
                misses = 0
            d = json.loads(script.exports_sync.readkey())
            key = (d.get('aes_key') or '').strip('"')
            iv = (d.get('aes_iv') or '').strip('"')
            if len(key) == 32 and len(iv) == 16 and (key, iv) != last:
                write_key(key, iv)
                last = (key, iv)
            misses = 0
        except Exception as e:
            misses += 1
            if misses == 3:
                print(f'reads failing ({e}) — game closed or gadget wedged?',
                      file=sys.stderr)
            # 3 consecutive failures -> drop the session so the next iteration
            # re-attaches (survives game restarts)
            if misses >= 3 and script is not None:
                try:
                    session.detach()
                except Exception:
                    pass
                session = script = None
                reattaches += 1
                if reattaches <= 3:
                    print('detached; will re-attach on the next poll',
                          file=sys.stderr)
                time.sleep(2.0)

    print('detaching…')
    try:
        if session:
            session.detach()
    except Exception:
        pass
    print('bye')


if __name__ == '__main__':
    main()
