"""Host-agnostic dispatch: (host, method, path, headers, body) -> response.

The game logic lives in `_pserver.py`; this only routes by host (the game's
three hostnames) and turns any failure into an explicit error — a game-host
request must **never** fall through to the real servers.
"""
from __future__ import annotations

import traceback

import _flowshim
import _pserver


def handle(host, method, path, headers=None, body=b'', addr=''):
    host = (host or '').lower()
    req = _flowshim.Request(host, method, path, headers, body)
    flow = _flowshim.Flow(req, _flowshim.Conn(addr))
    try:
        if host == _pserver.API_HOST:
            _pserver.log(f'>>> {method} {path}')
            _pserver.handle_api(flow)
        elif host == _pserver.RANK_HOST:
            _pserver.handle_rank(flow)
        elif host == _pserver.CDN_HOST:
            _pserver.handle_cdn(flow)
        else:
            return _flowshim.make(404, b'unknown host',
                                  {'Content-Type': 'text/plain'})
    except Exception:
        _pserver.log('CORE ERROR on', path, '\n' + traceback.format_exc())
        return _flowshim.make(502, b'private server error (see pserver.log)',
                              {'Content-Type': 'text/plain'})
    if flow.response is None:
        # e.g. a CDN miss while the harvest knob was on: no local copy and no
        # passthrough on a public server
        return _flowshim.make(404, b'', {'Content-Type': 'text/plain'})
    return flow.response


def load():
    """Load templates/charts/store (idempotent; the addon's `load` hook calls it)."""
    _pserver.load_data()
