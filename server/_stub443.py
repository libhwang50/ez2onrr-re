#!/usr/bin/env python3
"""Loop-proof stub for the game's RAW, un-proxied TLS channel.

The game talks to game1-rank.ez2game.co.kr:443 with its own TLS client that
ignores the WinHTTP proxy (verified: the addon never dials upstream, yet the
pcap shows direct TLS handshakes to that host around login and song entry).
`server/_rawchannel.sh` redirects the hostname and the raw IP here.

Why not mitmproxy in reverse mode: with the hostname redirected to 127.0.0.1, a
reverse proxy resolves its own *upstream* to 127.0.0.1 and opens connections to
itself for every request it does not intercept - an endless loop that exhausts
file descriptors. This stub never connects upstream, so that is impossible.

It logs every request (method, path, headers, body) to server/stub443.log and
answers with the same bodies the private server uses for the rank host, so the
first run tells us whether the channel is intercepted at all (and whether the
client accepts a certificate minted by the user's mitmproxy CA).

    sudo python3 server/_stub443.py [port]        # 443 by default
"""
import base64
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, 'server', 'data')
LOG = os.path.join(ROOT, 'server', 'stub443.log')
HOST = 'game1-rank.ez2game.co.kr'
CA = os.path.expanduser('~/.mitmproxy/mitmproxy-ca.pem')
if not os.path.exists(CA) and os.environ.get('SUDO_USER'):
    CA = os.path.join('/home', os.environ['SUDO_USER'], '.mitmproxy', 'mitmproxy-ca.pem')
CERT = os.path.join(DATA, 'stub443-cert.pem')
KEY = os.path.join(DATA, 'stub443-key.pem')
BATTLE = '3.37.247.33:9902'

_loglock = threading.Lock()


def log(*a):
    line = time.strftime('[%H:%M:%S] ') + ' '.join(str(x) for x in a) + '\n'
    with _loglock:
        with open(LOG, 'a', buffering=1) as f:
            f.write(line)
        sys.stdout.write(line)
        sys.stdout.flush()


def ensure_cert():
    """A leaf certificate for HOST, signed by the user's mitmproxy CA (already
    trusted by the game for the proxied hosts, so the same trust store should
    accept it here - if not, the client pins its own bundle)."""
    if os.path.exists(CERT) and os.path.exists(KEY):
        return
    os.makedirs(DATA, exist_ok=True)
    if not os.path.exists(CA):
        raise SystemExit(f'no mitmproxy CA at {CA}')
    csr = os.path.join(DATA, 'stub443.csr')
    subprocess.run(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', KEY, '-out', csr, '-subj', f'/CN={HOST}',
                    '-addext', f'subjectAltName=DNS:{HOST}'],
                   check=True, capture_output=True)
    subprocess.run(['openssl', 'x509', '-req', '-in', csr, '-CA', CA, '-CAkey', CA,
                    '-CAcreateserial', '-days', '825', '-copy_extensions', 'copy',
                    '-out', CERT], check=True, capture_output=True)
    os.remove(csr)
    log(f'generated a leaf cert for {HOST} signed by {CA}')


def rank_body(path, query):
    """The same bodies server/_pserver.py serves for the rank host."""
    q = query.get('data', [''])[0]
    arg = q.split(',')[0]
    if arg == 'get_battle_server_ip':
        return BATTLE.encode()
    if q.startswith('plf'):
        log(f'score upload: {urllib.parse.unquote(q)[:200]}')
        return b''
    if q.startswith('get') and arg[3:].isdigit():
        return b''
    return b''


def handle_request(raw, peer):
    """raw = the request bytes as received; answer HTTP/1.1."""
    try:
        head, _, body = raw.partition(b'\r\n\r\n')
    except Exception:
        head, body = raw, b''
    lines = head.split(b'\r\n')
    if not lines or not lines[0]:
        return None, raw
    try:
        method, target, _ = lines[0].decode('latin1').split(' ', 2)
    except Exception:
        return None, raw
    headers = {}
    for ln in lines[1:]:
        k, _, v = ln.decode('latin1').partition(':')
        if k:
            headers[k.strip().lower()] = v.strip()
    try:
        cl = int(headers.get('content-length', '0'))
    except Exception:
        cl = 0
    while len(body) < cl:
        break
    body = body[:cl]
    path, _, qs = target.partition('?')
    query = urllib.parse.parse_qs(qs)
    info = (f'{method} {target} from {peer}\n'
            f'    headers={json.dumps(headers)[:400]}\n')
    if body:
        info += (f'    body({len(body)}B)={body[:200]!r}\n'
                 f'    body hex={body[:160].hex()}\n')
    log(info)
    payload = rank_body(path, query) if query else b''
    if not query:
        payload = json.dumps({'result': 1}).encode()   # placeholder for API-ish paths
        log('    (no ?data= query — could be an API call on this channel; '
            'answered with a placeholder {"result":1})')
    resp = (b'HTTP/1.1 200 OK\r\n'
            b'Content-Type: application/json\r\n'
            b'Content-Length: ' + str(len(payload)).encode() + b'\r\n'
            b'Connection: close\r\n\r\n' + payload)
    return resp, raw


def serve_client(conn, addr, ctx):
    peer = f'{addr[0]}:{addr[1]}'
    try:
        tls = ctx.wrap_socket(conn, server_side=True)
    except ssl.SSLError as e:
        log(f'TLS FAILED from {peer}: {e}  '
            f'(client rejected the cert / pins its own CA bundle?)')
        try:
            conn.close()
        except Exception:
            pass
        return
    except Exception as e:
        log(f'TLS error from {peer}: {e!r}')
        try:
            conn.close()
        except Exception:
            pass
        return
    sn = None
    try:
        sn = tls.server_hostname
    except Exception:
        pass
    log(f'TLS OK from {peer} sni={sn} cipher={tls.cipher()[0] if tls.cipher() else "?"}')
    try:
        tls.settimeout(20)
        while True:
            data = b''
            while b'\r\n\r\n' not in data:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                data += chunk
                if data.startswith(b'PRI * HTTP/2.0'):
                    log('    HTTP/2 preface! this client speaks h2 — the stub '
                        'must be upgraded or forced to http/1.1')
                    return
            if not data:
                break
            resp, _ = handle_request(data, peer)
            if resp is None:
                break
            try:
                tls.sendall(resp)
            except Exception as e:
                log(f'send failed to {peer}: {e!r}')
                break
            if b'Connection: close' in resp:
                break
    except Exception as e:
        log(f'client {peer} error: {e!r}')
    finally:
        try:
            tls.close()
        except Exception:
            pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 443
    ensure_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    ctx.set_alpn_protocols(['http/1.1'])
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', port))
    srv.listen(64)
    log(f'stub443 listening on :{port} for {HOST} (cert={CERT}, CA={CA})')
    while True:
        try:
            conn, addr = srv.accept()
        except Exception as e:
            log(f'accept error: {e!r}')
            continue
        threading.Thread(target=serve_client, args=(conn, addr, ctx),
                         daemon=True).start()


if __name__ == '__main__':
    main()
