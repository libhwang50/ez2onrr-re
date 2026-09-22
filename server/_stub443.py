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
import json
import os
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


def parse_clienthello(data):
    """Best-effort extraction of SNI and the offered ALPN list from a
    ClientHello record. Used to see what the game's custom TLS client asks for
    (a mismatch here makes the client abort right after the handshake)."""
    out = {'sni': None, 'alpn': [], 'version': None, 'ciphers': 0}
    try:
        if len(data) < 6 or data[0] != 0x16:
            return out, 'not a TLS handshake record'
        # record: type(1) ver(2) len(2) ; handshake: type(1) len(3)
        hl = data[5:]
        if hl[0] != 0x01:
            return out, f'handshake type {hl[0]:#x} (not ClientHello)'
        p = 4
        out['version'] = hl[p:p + 2].hex()      # legacy_version
        p += 2 + 32                             # random
        sid_len = hl[p]; p += 1 + sid_len
        cs_len = int.from_bytes(hl[p:p + 2], 'big'); p += 2
        out['ciphers'] = cs_len // 2
        p += cs_len
        comp_len = hl[p]; p += 1 + comp_len
        ext_total = int.from_bytes(hl[p:p + 2], 'big'); p += 2
        end = min(len(hl), p + ext_total)
        while p + 4 <= end:
            et = int.from_bytes(hl[p:p + 2], 'big')
            el = int.from_bytes(hl[p + 2:p + 4], 'big')
            body = hl[p + 4:p + 4 + el]
            if et == 0 and len(body) >= 5:                     # server_name
                nl = int.from_bytes(body[3:5], 'big')
                out['sni'] = body[5:5 + nl].decode('latin1', 'replace')
            elif et == 16 and len(body) >= 2:                  # ALPN
                q = 2
                while q < len(body):
                    n = body[q]; q += 1
                    out['alpn'].append(body[q:q + n].decode('latin1', 'replace'))
                    q += n
            elif et == 43:                                     # supported_versions
                out['supported_versions'] = [body[i + 1:i + 3].hex()
                                             for i in range(1, len(body) - 2, 2)]
            p += 4 + el
    except Exception as e:
        return out, f'parse error {e!r}'
    return out, None


def peek_clienthello(conn, timeout=4.0):
    """MSG_PEEK so the bytes stay in the buffer for ssl.wrap_socket."""
    conn.settimeout(timeout)
    waited = 0.0
    while waited < timeout:
        try:
            data = conn.recv(65536, socket.MSG_PEEK)
        except (socket.timeout, ssl.SSLError):
            break
        except Exception:
            break
        if len(data) >= 5:
            need = 5 + int.from_bytes(data[3:5], 'big')
            if len(data) >= need:
                return data[:need]
        time.sleep(0.05)
        waited += 0.05
    return data if 'data' in dir() else b''


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
    hello = peek_clienthello(conn)
    if hello:
        info, err = parse_clienthello(hello)
        log(f'ClientHello from {peer}: sni={info.get("sni")!r} '
            f'alpn={info.get("alpn")} ciphers={info.get("ciphers")} '
            f'legacy_ver={info.get("version")} '
            f'supported={info.get("supported_versions")}' + (f'  [{err}]' if err else ''))
    else:
        log(f'{peer}: no ClientHello seen before the handshake')
    try:
        tls = ctx.wrap_socket(conn, server_side=True)
    except Exception as e:
        log(f'TLS FAILED from {peer}: {e!r}  (client rejected the certificate, '
            f'or ALPN mismatch)')
        try:
            conn.close()
        except Exception:
            pass
        return
    log(f'TLS OK from {peer} alpn={tls.selected_alpn_protocol()!r} '
        f'cipher={tls.cipher()[0] if tls.cipher() else "?"} '
        f'version={tls.version()}')
    try:
        tls.settimeout(15)
        total = b''
        while True:
            try:
                chunk = tls.recv(65536)
            except socket.timeout:
                log(f'{peer}: read timeout after {len(total)}B total')
                if total:
                    log(f'    partial: {total[:300]!r}')
                break
            except Exception as e:
                log(f'{peer}: recv raised {e!r} after {len(total)}B total; '
                    f'got so far: {total[:300]!r}')
                break
            if not chunk:
                log(f'{peer}: peer closed after {len(total)}B total'
                    + (f'; data was {total[:300]!r}' if total else
                       ' (closed WITHOUT sending a request - likely an ALPN '
                       'mismatch or a pre-open/probe connection)'))
                break
            total += chunk
            log(f'{peer}: {len(chunk)}B chunk (hex {chunk[:24].hex()}...): '
                f'{chunk[:200]!r}')
            if chunk.startswith(b'PRI * HTTP/2.0'):
                log('    HTTP/2 prior-knowledge preface!')
                break
            if b'\r\n\r\n' in total or b'\n\n' in total:
                head, _, body = total.replace(b'\n\n', b'\r\n\r\n', 1).partition(b'\r\n\r\n')
                cl = 0
                for ln in head.splitlines():
                    if ln.lower().startswith(b'content-length:'):
                        cl = int(ln.split(b':', 1)[1].strip())
                if len(body) < cl:
                    continue
                resp, _ = handle_request(total, peer)
                if resp:
                    try:
                        tls.sendall(resp)
                        log(f'{peer}: answered {len(resp)}B')
                    except Exception as e:
                        log(f'{peer}: send failed {e!r}')
                break
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
