#!/usr/bin/env python3
"""Capture the game's raw packet/battle channel (default 3.37.247.33:9902) and
read it.

Why: this is where the client hands its session key to the *battle* server. The
`zf` literals `[9903]sendKeyDataStr:`, `sendaes,`, `[AES 키 전송 완료]` and
`s2c_aes_connect_completed` describe the exchange, and the packet framing is
`aes,<command>[,<args>]` (§3.1). Catching `sendaes,` would show how the
key travels on this channel and whether it is RSA-wrapped (compare with
`c2s_login.data`, the API server's copy). Earlier notes here called this the
"server-side audit" of `bundleCryptKey`; that reading is superseded — the bCK is
validated **locally** (§3.2).

The address is served by OUR rank stub (`get_battle_server_ip`), so redirect it
here with:

    echo '127.0.0.1:9902' > server/data/battle_server.txt
    python3 server/re/_stub9902.py 9902

then relaunch the game, log in (private server) and load a chart. Everything the
client sends is logged to server/stub9902.log as hex + printable ASCII, and any
zf-layer AES-CBC (zf.aes_key/aes_iv, ASCII bytes) is decrypted when the
ciphertext length fits. Nothing is answered by default — the request itself is
what we need first.
"""
import json
import os
import socket
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # repo root
LOG = os.path.join(ROOT, 'server', 'stub9902.log')
KEYFILE = os.path.join(ROOT, 'server', 'session_key.json')

REPLY = os.environ.get('EZ2_9902_REPLY', '')     # hex bytes to answer with, if any
# set EZ2_9902_UPSTREAM=3.37.247.33:9902 to relay to the real server while
# capturing both directions (the load then SUCCEEDS, which is what we want for
# learning the accepted exchange; leave it unset to log-only)
UPSTREAM = os.environ.get('EZ2_9902_UPSTREAM', '')

_lock = threading.Lock()


def log(*a):
    line = time.strftime('[%H:%M:%S] ') + ' '.join(str(x) for x in a) + '\n'
    with _lock:
        with open(LOG, 'a', buffering=1) as f:
            f.write(line)
        sys.stdout.write(line)
        sys.stdout.flush()


def session_key():
    try:
        d = json.load(open(KEYFILE))
        return d['aes_key'].encode(), d['aes_iv'].encode()
    except Exception:
        return None


def try_zf_decrypt_direction(data, tag):
    try_zf_decrypt(data)


def try_zf_decrypt(data):
    """The raw channel is described as zf RSA+AES: try the session key as the
    AES-256-CBC layer over the whole payload and over common small offsets."""
    sk = session_key()
    if not sk:
        return
    try:
        from Crypto.Cipher import AES
    except Exception:
        return
    key, iv = sk
    for off in (0, 4, 6, 8, 16):
        body = data[off:]
        if len(body) < 32 or len(body) % 16:
            continue
        try:
            pt = AES.new(key, AES.MODE_CBC, iv).decrypt(body)
        except Exception:
            continue
        n = pt[-1]
        if 1 <= n <= 16 and pt[-n:] == bytes([n]) * n:
            log(f'    !! AES-CBC decrypts at offset {off}: {pt[:-n][:400]!r}')


def pump_upstream(conn, up, tag, forward):
    """Log (and optionally forward) one direction of the relayed channel."""
    total = b''
    try:
        while True:
            data = up.recv(65536)
            if not data:
                break
            total += data
            log(f'  <<< {tag} {len(data)}B: {data[:120].hex()}'
                + (f'  ascii="{"".join(chr(b) if 32 <= b < 127 else "." for b in data[:80])}"' if data[:1] not in (b"\x16", b"\x17") else ""))
            try_zf_decrypt_direction(total, tag)
            if forward:
                conn.sendall(data)
    except Exception as e:
        log(f'  <<< {tag} ended: {e!r} total={len(total)}B')
    return total


def handle_relay(conn, addr, upstream):
    """Transparent capturing relay to the real battle server: the load should
    SUCCEED (the real server does the audit) and we see both directions."""
    peer = f'{addr[0]}:{addr[1]}'
    log(f'CONNECT {peer} -> relaying to {upstream}')
    try:
        host, _, port = upstream.rpartition(':')
        up = socket.create_connection((host, int(port)), 10)
    except Exception as e:
        log(f'  upstream connect failed: {e!r} (logging only)')
        return handle(conn, addr)
    up.settimeout(60); conn.settimeout(60)
    t1 = threading.Thread(target=pump_upstream, args=(conn, up, 'server', True), daemon=True)
    t1.start()
    total = b''
    try:
        while True:
            try:
                data = conn.recv(65536)
            except socket.timeout:
                break
            if not data:
                break
            total += data
            log(f'  >>> client {len(data)}B: {data[:160].hex()}'
                + (f'  ascii="{"".join(chr(b) if 32 <= b < 127 else "." for b in data[:80])}"' if data[:1] not in (b"\x16", b"\x17") else ""))
            try_zf_decrypt_direction(total, 'client')
            up.sendall(data)
    except Exception as e:
        log(f'  >>> client ended: {e!r} total={len(total)}B')
    finally:
        for s in (conn, up):
            try: s.close()
            except Exception: pass
    if total:
        open(os.path.join(ROOT, 'server', 'stub9902_client.bin'), 'wb').write(total)
        log(f'  saved client stream {len(total)}B -> server/stub9902_client.bin')


def handle(conn, addr):
    peer = f'{addr[0]}:{addr[1]}'
    log(f'CONNECT {peer}')
    conn.settimeout(30)
    total = b''
    try:
        while True:
            try:
                chunk = conn.recv(65536)
            except socket.timeout:
                log(f'  {peer}: idle (no more data) total={len(total)}B')
                break
            if not chunk:
                log(f'  {peer}: closed, total={len(total)}B')
                break
            total += chunk
            log(f'  {peer}: {len(chunk)}B chunk'
                + (f' (first 32 hex {chunk[:32].hex()})' if len(chunk) >= 32 else ''))
            ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk[:400])
            log(f'      ascii: {ascii_repr}')
            try_zf_decrypt(total)
            if REPLY:
                try:
                    conn.sendall(bytes.fromhex(REPLY))
                    log(f'  {peer}: sent {len(REPLY)//2}B reply')
                except Exception as e:
                    log(f'  {peer}: reply failed {e!r}')
    except Exception as e:
        log(f'  {peer}: error {e!r}')
    finally:
        try:
            conn.close()
        except Exception:
            pass
    if total:
        with open(os.path.join(ROOT, 'server', 'stub9902_last.bin'), 'wb') as f:
            f.write(total)
        log(f'  saved {len(total)}B to server/stub9902_last.bin')
        n = len(total)
        log(f'  full hex ({n}B): {total[:600].hex()}')


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9902
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', port))
    srv.listen(16)
    log(f'stub9902 listening on :{port}'
        + (f' (capturing relay -> {UPSTREAM})' if UPSTREAM else
           (f' (auto-reply {REPLY})' if REPLY else ' (log only, no reply)')))
    while True:
        try:
            conn, addr = srv.accept()
        except Exception as e:
            log(f'accept error {e!r}')
            continue
        if UPSTREAM:
            threading.Thread(target=handle_relay, args=(conn, addr, UPSTREAM),
                             daemon=True).start()
        else:
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == '__main__':
    main()
