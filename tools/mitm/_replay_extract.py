"""
Read a native mitmproxy dump (-w file) and emit one JSONL record per HTTP flow,
in order, with full request/response bodies (decoded) for the EZ2ON API.

Usage:
    mitmdump -nr "$SRC" -s tools/mitm/_replay_extract.py

Writes:  $EZ2_REPLAY_OUT/flows.jsonl
         mitm_parsed/replay/body_<n>_req.bin / _resp.bin
"""
import base64
import json
import os

from mitmproxy import http

OUT = os.environ.get("EZ2_REPLAY_OUT", os.path.join("mitm_parsed", "replay"))
SRC = os.environ.get("EZ2_REPLAY_SRC", "mitm_parsed/flow_dump")
os.makedirs(OUT, exist_ok=True)
LOG = open(os.path.join(OUT, "flows.jsonl"), "w", encoding="utf-8")

_n = 0


def _save(name: str, data: bytes) -> str:
    path = os.path.join(OUT, name)
    with open(path, "wb") as f:
        f.write(data)
    return path


def response(flow: http.HTTPFlow):
    global _n
    _n += 1
    req, resp = flow.request, flow.response
    host = (req.host or "").lower()
    rec = {
        "n": _n,
        "host": host,
        "method": req.method,
        "scheme": req.scheme,
        "path": req.path,
        "url": req.pretty_url,
        "status": resp.status_code if resp else None,
        "req_headers": dict(req.headers),
        "resp_headers": dict(resp.headers) if resp else {},
    }
    rb = req.raw_content or b""
    sb = resp.raw_content or b""
    if rb:
        rec["req_body_file"] = os.path.basename(
            _save(f"body_{_n:03d}_req.bin", rb))
        try:
            rec["req_body_text"] = rb.decode("utf-8")
        except UnicodeDecodeError:
            rec["req_body_b64"] = base64.b64encode(rb).decode()
    if sb:
        rec["resp_body_file"] = os.path.basename(
            _save(f"body_{_n:03d}_resp.bin", sb))
        body = bytes(resp.content)  # content-decoded (gzip etc.)
        try:
            rec["resp_body_text"] = body.decode("utf-8")
        except UnicodeDecodeError:
            rec["resp_body_len"] = len(body)
    LOG.write(json.dumps(rec, ensure_ascii=False) + "\n")
    LOG.flush()


def done():
    LOG.close()
    print(f"[_replay_extract] {_n} flows -> {OUT}/flows.jsonl")
