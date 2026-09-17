"""
mitmdump addon: capture + (optionally) rewrite EZ2ON CDN/API traffic.

Run:   mitmdump -s _cdn_rewrite.py -q
Control file `_rewrite.json` (optional), e.g.:
  {"op": "none"}      -> pass through (control run)
  {"op": "zero16"}    -> zero the first 16 bytes of each CDN body
  {"op": "zero32"}    -> zero the first 32 bytes
  {"op": "trunc16"}   -> drop the last 16 bytes
  {"op": "trunc32"}   -> drop the last 32 bytes
  {"op": "zeros"}     -> all-zero body, same length
Bodies are saved under mitm_live/ and every flow is appended to mitm_live/log.jsonl
"""
import hashlib, json, os, time
from mitmproxy import http

OUT = "mitm_live"
os.makedirs(OUT, exist_ok=True)
LOG = open(os.path.join(OUT, "log.jsonl"), "a", buffering=1)


def _cfg():
    try:
        return json.load(open("_rewrite.json"))
    except Exception:
        return {}


def request(flow: http.HTTPFlow):
    h = flow.request.pretty_host
    if "ez2game.co.kr" in h:
        LOG.write(json.dumps({"t": time.time(), "req": h + flow.request.path[:100]}) + "\n")


def response(flow: http.HTTPFlow):
    h = flow.request.pretty_host
    if "ez2game.co.kr" not in h:
        return
    body = flow.response.content or b""
    rec = {
        "t": time.time(), "host": h, "path": flow.request.path[:90],
        "status": flow.response.status_code, "len": len(body),
        "sha": hashlib.sha256(body).hexdigest()[:16],
    }
    kind = "cdn" if "cdn" in h else ("api" if "play" in h else "other")
    rec["kind"] = kind
    p = os.path.join(OUT, "%s_%s.bin" % (kind, rec["sha"]))
    if not os.path.exists(p):
        open(p, "wb").write(body)
    rec["saved"] = p

    cfg = _cfg()
    op = cfg.get("op")
    m = cfg.get("match")
    if m and m not in flow.request.path:
        rec["skipped"] = "match"
        LOG.write(json.dumps(rec) + "\n")
        return
    if kind == "cdn" and op and op != "none" and len(body):
        b = bytearray(body)
        off = int(cfg.get("offset", 0))
        if op == "zero16" and len(b) >= off + 16:
            b[off:off+16] = b"\x00" * 16
        elif op == "zero32" and len(b) >= off + 32:
            b[off:off+32] = b"\x00" * 32
        elif op == "trunc16" and len(b) > 16:
            b = b[:-16]
        elif op == "trunc32" and len(b) > 32:
            b = b[:-32]
        elif op == "zeros":
            b = bytes(len(b))
        flow.response.content = bytes(b)
        rec["rewrote"] = op
        rec["newlen"] = len(b)
    LOG.write(json.dumps(rec) + "\n")
