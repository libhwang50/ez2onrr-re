"""Frida session-key bridge for the private server.

Polls zf.aes_key / zf.aes_iv (the API session key the client generates at
login — zf.gnf: RNGCryptoServiceProvider -> BitConverter.ToString -> hex)
at 1 Hz through the Gadget and writes every change to
server/session_key.json, which server/_pserver.py reads per request.

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


def _stop(_sig, _frm):
    global _running
    _running = False


def write_key(key, iv):
    tmp = OUT + '.tmp'
    json.dump({'aes_key': key, 'aes_iv': iv, 't': time.time()},
              open(tmp, 'w'))
    os.replace(tmp, OUT)
    print(f'[{time.strftime("%H:%M:%S")}] session key -> {OUT}: {key} / {iv}')


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGHUP, _stop)

    src = open(DRIVER).read()
    dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
    session = dev.attach('Gadget')
    script = session.create_script(src)
    script.load()
    print('attached to Gadget; polling zf.aes_key/aes_iv at 1 Hz')

    # a fresh harvester run means a fresh game session — drop any stale key so
    # the server never encrypts the login response under the previous session
    if os.path.exists(OUT):
        os.remove(OUT)
        print('removed stale session_key.json')

    last = None
    misses = 0
    while _running:
        time.sleep(1.0)
        try:
            d = json.loads(script.exports_sync.readkey())
            key = (d.get('aes_key') or '').strip('"')
            iv = (d.get('aes_iv') or '').strip('"')
            if len(key) == 32 and len(iv) == 16 and (key, iv) != last:
                write_key(key, iv)
                last = (key, iv)
            misses = 0
        except Exception as e:
            misses += 1
            if misses <= 3:
                print(f'read failed: {e}', file=sys.stderr)
            if misses in (3, 30):
                print('… read path may be dead; keep this running only while '
                      'the game is healthy', file=sys.stderr)

    print('detaching…')
    try:
        session.detach()
    except Exception:
        pass
    print('bye')


if __name__ == '__main__':
    main()
