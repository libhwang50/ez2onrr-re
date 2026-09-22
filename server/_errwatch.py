"""Error-popup watcher for the private server.

While the game runs, periodically scans its rw- memory for the UTF-16 string
'ErrCode' — the in-game error popup embeds a detailed message (the part too
long to screenshot). When a new occurrence appears, reads a window around it
(clamped to the enclosing mapping — never straddles unmapped pages) and appends
the decoded text to server/errwatch.log.

Uses ONE Frida session (the game is known to die on a third concurrent attach)
and attaches only after the Gadget port has been stable for a grace period —
an attach during early startup also kills the game (see tools/README.md).

Run alongside the game:
    .venv/bin/python server/_errwatch.py
"""
import os
import signal
import time

import frida

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(ROOT, 'server', 'errwatch.log')
DRIVER = os.path.join(ROOT, 'tools', 'build', '_errwatch_run.js')
PORT = 27042
GRACE = float(os.environ.get('EZ2_HARVEST_GRACE', '15'))

_running = True
_seen = set()


def _stop(_sig, _frm):
    global _running
    _running = False


def log(msg):
    line = f'[{time.strftime("%H:%M:%S")}] {msg}'
    print(line, flush=True)
    with open(LOG, 'a') as f:
        f.write(line + '\n')


def gadget_port_open():
    import socket
    try:
        with socket.create_connection(('127.0.0.1', PORT), timeout=0.5):
            return True
    except OSError:
        return False


def wait_for_stable_game():
    while _running:
        if not gadget_port_open():
            time.sleep(0.5)
            continue
        t0 = time.time()
        stable = True
        while _running and time.time() - t0 < GRACE:
            if not gadget_port_open():
                log('game vanished during the grace window; waiting')
                time.sleep(3)
                stable = False
                break
            time.sleep(0.5)
        if not _running:
            return False
        if stable:
            return True
    return False


DRIVER_SRC = '''
rpc.exports.scanerr = function () {
  function utf16hex(s) { let h=''; for (const ch of s) { const c=ch.charCodeAt(0);
    h += (c&0xff).toString(16).padStart(2,'0') + ((c>>8)&0xff).toString(16).padStart(2,'0'); } return h; }
  const pat = utf16hex('ErrCode').match(/../g).join(' ');
  const hits = [];
  for (const r of Process.enumerateRanges({ protection: 'rw-', coalesce: true })) {
    if (r.size < 64) continue;
    try { for (const m of Memory.scanSync(r.base, r.size, pat)) {
      hits.push({ addr: m.address.toString(), base: r.base.toString(), size: r.size });
      if (hits.length >= 60) return hits;
    } } catch (e) {}
  }
  return hits;
};
rpc.exports.readwin = function (addr, lo, hi) {
  const p = ptr(addr);
  let range = null;
  for (const r of Process.enumerateRanges({ protection: 'rw-', coalesce: true })) {
    if (p.compare(r.base) >= 0 && p.compare(r.base.add(r.size)) < 0) { range = r; break; }
  }
  if (!range) return null;
  let start = p.sub(lo); if (start.compare(range.base) < 0) start = range.base;
  let end = p.add(hi); const rend = range.base.add(range.size);
  if (end.compare(rend) > 0) end = rend;
  const u = new Uint8Array(start.readByteArray(end.sub(start).toInt32()));
  let s = '';
  for (let i = 0; i + 1 < u.length; i += 2) {
    const c = u[i] | (u[i+1] << 8);
    s += (c >= 32 && c !== 0xfffe) ? String.fromCharCode(c) : '\\u00b7';
  }
  return { start: start.toString(), text: s };
};
'''


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    log('errwatch started (attaches once the game is past its startup window)')

    session = script = None
    while _running:
        time.sleep(3)
        try:
            if script is None:
                if not wait_for_stable_game():
                    break
                src = DRIVER_SRC  # self-contained; no bridge needed for raw scans
                dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
                session = dev.attach('Gadget')
                script = session.create_script(src)
                script.load()
                log('attached; watching for error popups')
            hits = script.exports_sync.scanerr()
            for h in hits:
                if h['addr'] in _seen:
                    continue
                _seen.add(h['addr'])
                w = script.exports_sync.readwin(h['addr'], 0x400, 0x800)
                log(f'NEW ErrCode hit at {h["addr"]}:\n'
                    + (w['text'] if w else '<read failed>'))
        except Exception as e:
            log(f'watch error: {e}')
            try:
                if session:
                    session.detach()
            except Exception:
                pass
            session = script = None
            time.sleep(3)

    try:
        if session:
            session.detach()
    except Exception:
        pass
    print('bye', flush=True)


if __name__ == '__main__':
    main()
