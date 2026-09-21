"""
mitmdump addon: dumb full capture of every HTTP flow, ordered, for offline analysis.

Run:
    mitmdump -s tools/mitm/_capture_all.py -w mitm_live/cap_$(date +%Y%m%d_%H%M%S).mitm

The `-w` file is the lossless native record (keep it); this addon supplements it with
a query-friendly, human-scannable corpus:

    <dir>/flows.jsonl      one record per flow, in order (run marker first)
    <dir>/bodies/<sha>.bin raw bodies, deduped by sha256, referenced from the records

Bodies ≤ INLINE_MAX bytes are also inlined in the record (base64, or text when it
decodes cleanly), so API request/response pairs are greppable without touching the
body store. CDN payloads are sha-only.

Output directory defaults to mitm_live/cap_<UTC timestamp>/; override with
EZ2_CAPTURE_DIR.

Notes:
  * Errors (no response: TLS trust failure, abort, timeout) are logged too — they
    matter for a private-server implementation.
  * Only HTTP(S) is seen here. The control channel (TCP 3.37.247.33:4649) and any
    other raw TCP bypass mitmproxy entirely.
"""
import base64
import hashlib
import json
import os
import time
from mitmproxy import http, version

INLINE_MAX = 4096

_ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
OUT = os.environ.get("EZ2_CAPTURE_DIR") or os.path.join("mitm_live", "cap_" + _ts)
BODY_DIR = os.path.join(OUT, "bodies")
os.makedirs(BODY_DIR, exist_ok=True)

LOG = open(os.path.join(OUT, "flows.jsonl"), "a", buffering=1)
_counts = {"flow": 0, "body": 0, "err": 0, "inline": 0, "dedup": 0}


def _rec(**kw):
    LOG.write(json.dumps(kw, ensure_ascii=False) + "\n")


def _classify(host: str) -> str:
    if "game1-play.ez2game.co.kr" in host or "game1-test" in host:
        return "api"
    if "cdn" in host and "ez2game" in host:
        return "cdn"
    if "ez2game" in host:
        return "ez2other"
    return "other"


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _save_body(b: bytes) -> dict:
    """Store raw bytes once; return a descriptor for the record."""
    sha = _sha(b)
    path = os.path.join(BODY_DIR, sha + ".bin")
    if os.path.exists(path):
        _counts["dedup"] += 1
    else:
        with open(path, "wb") as f:
            f.write(b)
        _counts["body"] += 1
    d = {"sha256": sha, "len": len(b), "file": os.path.relpath(path, OUT)}
    if len(b) <= INLINE_MAX:
        _counts["inline"] += 1
        try:
            d["text"] = b.decode("utf-8")
        except UnicodeDecodeError:
            d["b64"] = base64.b64encode(b).decode()
    return d


def _hdrs(h) -> dict:
    return {k: v for k, v in h.items()}


def _conn(flow: http.HTTPFlow) -> dict:
    c, s = flow.client_conn, flow.server_conn
    out = {}
    if c and c.peername:
        out["client"] = "%s:%d" % c.peername
    if s and s.address:
        out["server"] = "%s:%d" % s.address
    if s:
        out["sni"] = s.sni
    return out


_rec(event="run_start", mitmproxy=version.MITMPROXY_VERSION, out_dir=OUT,
     t=time.time())


def response(flow: http.HTTPFlow):
    _counts["flow"] += 1
    req, resp = flow.request, flow.response
    host = (req.host or "").lower()
    kind = _classify(host)

    rec = {
        "event": "response",
        "n": _counts["flow"],
        "t_start": req.timestamp_start,
        "t_end": resp.timestamp_end,
        "dur": (resp.timestamp_end - req.timestamp_start)
               if resp.timestamp_end else None,
        "kind": kind,
        "method": req.method,
        "http_version": req.http_version,
        "host": host,
        "port": req.port,
        "scheme": req.scheme,
        "path": req.path,
        "url": req.pretty_url,
        "status": resp.status_code,
        "reason": resp.reason,
    }
    rec.update(_conn(flow))
    rec["req_headers"] = _hdrs(req.headers)
    rec["resp_headers"] = _hdrs(resp.headers)

    rb = req.raw_content or b""
    sb = resp.raw_content or b""
    if rb:
        rec["req_body"] = _save_body(rb)
    if sb:
        rec["resp_body"] = _save_body(sb)
        # decompressed view, if the wire body was content-encoded
        if resp.content != resp.raw_content:
            rec["resp_body_decoded"] = _save_body(bytes(resp.content))
    _rec(**rec)


def error(flow: http.HTTPFlow):
    _counts["err"] += 1
    req = flow.request
    rec = {
        "event": "error",
        "t": time.time(),
        "kind": _classify((req.host or "").lower()),
        "method": req.method,
        "host": req.host,
        "path": req.path,
        "error": flow.error.msg if flow.error else "unknown",
    }
    rec.update(_conn(flow))
    _rec(**rec)


def websocket_message(flow: http.HTTPFlow):
    msg = flow.websocket.messages[-1] if flow.websocket else None
    if msg is None:
        return
    d = _save_body(bytes(msg.content))
    _rec(event="ws_message", t=time.time(), from_client=msg.from_client,
         opcode=msg.type_code, **d)


def done():
    _rec(event="run_end", t=time.time(), **_counts)
    print("[_capture_all] flows=%(flow)d errors=%(err)d bodies=%(body)d "
          "(dedup hits: %(dedup)d, inlined: %(inline)d) -> %s"
          % dict(_counts, out=OUT))
