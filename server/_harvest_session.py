"""Frida session-key bridge for the private server.

Polls zf.aes_key / zf.aes_iv (the API session key the client generates at
login — zf.gnf: RNGCryptoServiceProvider -> hex, AGENTS.md §3.1) at 1 Hz
through the Gadget and writes every change to server/session_key.json, which
server/_pserver.py reads per request.

Auto-re-attaches when the game restarts: without this the server keeps
encrypting under a stale key and the client silently falls back to the
official servers (or fails).

⚠ Attaching while the game is still starting up (before the main window
exists) kills the process instantly — no crash handler, just gone. So the
harvester watches the Gadget's TCP port and only attaches after it has been
listening continuously for a grace period (EZ2_HARVEST_GRACE, default 15 s).
Start the harvester once and leave it running; ordering with the game no
longer matters.

Exits cleanly on Ctrl-C (detaches — see tools/README.md).
"""
import json
import os
import signal
import socket
import sys
import time

import frida

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'server', 'session_key.json')
DRIVER = os.path.join(ROOT, 'tools', 'build', '_sesskey_run.js')
HOST = '127.0.0.1'
PORT = 27042
GRACE = float(os.environ.get('EZ2_HARVEST_GRACE', '15'))
COOLDOWN = float(os.environ.get('EZ2_HARVEST_COOLDOWN', '5'))

_running = True


def _stop(_sig, _frm):
    global _running
    _running = False


def log(msg):
    print(f'[{time.strftime("%H:%M:%S")}] {msg}', flush=True)


def write_key(key, iv):
    tmp = OUT + '.tmp'
    json.dump({'aes_key': key, 'aes_iv': iv, 't': time.time()},
              open(tmp, 'w'))
    os.replace(tmp, OUT)
    log(f'session key -> {OUT}: {key} / {iv}')


def gadget_port_open():
    """True if something is listening on the Gadget port (cheap host-side probe)."""
    try:
        with socket.create_connection((HOST, PORT), timeout=0.5):
            return True
    except OSError:
        return False


def wait_for_stable_game():
    """Block until a gadget has been listening continuously for GRACE seconds.

    Attaching during the game's early startup kills it, so we wait out the
    fragile window without touching the process at all. If the game dies and
    relaunches mid-grace, the clock restarts from the fresh launch."""
    while _running:
        if not gadget_port_open():
            time.sleep(0.5)
            continue
        t0 = time.time()
        stable = True
        while _running and time.time() - t0 < GRACE:
            if not gadget_port_open():
                log('game vanished during the startup grace window; '
                    'waiting for the next launch')
                time.sleep(COOLDOWN)
                stable = False
                break
            time.sleep(0.5)
        if not _running:
            return
        if stable:
            return


def attach():
    """Attach to the Gadget and load the read driver. Returns (session, script)."""
    src = open(DRIVER).read()
    dev = frida.get_device_manager().add_remote_device(f'{HOST}:{PORT}')
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
        print('removed stale session_key.json', flush=True)

    log(f'watching the Gadget port (attach grace {GRACE:.0f}s, '
        f'cooldown {COOLDOWN:.0f}s)')

    session = script = None
    last = None
    misses = 0
    hunt_done = False
    while _running:
        time.sleep(1.0)
        try:
            if script is None:
                wait_for_stable_game()
                if not _running:
                    break
                session, script = attach()
                log('attached; polling zf.aes_key/aes_iv at 1 Hz')
                misses = 0
            d = json.loads(script.exports_sync.readkey())
            key = (d.get('aes_key') or '').strip('"')
            iv = (d.get('aes_iv') or '').strip('"')
            if len(key) == 32 and len(iv) == 16 and (key, iv) != last:
                write_key(key, iv)
                last = (key, iv)
                # one-shot error-site hunt (env-gated): runs the heavy literal
                # scan INSIDE this session - never open a second Frida session
                if os.environ.get('EZ2_HUNT') and not hunt_done:
                    hunt_done = True
                    log('EZ2_HUNT: hunting the error site (this blocks key '
                        'polling for a couple of minutes)…')
                    try:
                        res = script.exports_sync.hunt('게임 파일이 손상되었습니다')
                        open(os.path.join(ROOT, 'server', 'hunt_result.json'), 'w').write(res)
                        log('hunt result -> server/hunt_result.json')
                    except Exception as e:
                        log(f'hunt failed: {e}')
            misses = 0
        except Exception as e:
            misses += 1
            if misses == 3:
                log(f'reads failing ({e}) — game closed or gadget wedged?')
            # 3 consecutive failures -> the game is gone; drop the session AND
            # the stale key (a relaunch generates a new one - serving the old
            # key made the client fail its login instantly with the NRE popup)
            if misses >= 3 and script is not None:
                try:
                    session.detach()
                except Exception:
                    pass
                session = script = None
                if os.path.exists(OUT):
                    os.remove(OUT)
                    log('game gone - removed stale session_key.json')
                log('detached; will re-attach once the next game is past '
                    'its startup window')
                time.sleep(COOLDOWN)

    print('detaching…', flush=True)
    try:
        if session:
            session.detach()
    except Exception:
        pass
    print('bye')


if __name__ == '__main__':
    main()
