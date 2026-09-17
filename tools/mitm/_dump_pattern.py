#!/usr/bin/env python3
"""mitmproxy addon: dump every c2s_get_pattern_file request+response pair."""
import json, os
from mitmproxy import http

OUT = os.path.join(os.getcwd(), "mitm_parsed")
os.makedirs(OUT, exist_ok=True)
n = {"i": 0}

def response(flow: http.HTTPFlow):
    if "c2s_get_pattern_file" not in flow.request.path:
        return
    req = flow.request
    resp = flow.response
    i = n["i"]; n["i"] += 1
    rec = {
        "id": i,
        "url": req.pretty_url,
        "req_headers": dict(req.headers),
        "req_body_hex": (req.content or b"").hex(),
        "req_body_text": None,
        "resp_status": resp.status_code if resp else None,
        "resp_headers": dict(resp.headers) if resp else None,
        "resp_body_hex": (resp.content or b"").hex() if resp else None,
        "resp_body_text": None,
    }
    try: rec["req_body_text"] = (req.content or b"").decode("utf-8", "ignore")
    except Exception: pass
    if resp and resp.content:
        try: rec["resp_body_text"] = bytes(resp.content).decode("utf-8", "ignore")
        except Exception: pass
    with open(os.path.join(OUT, f"pattern_{i:03d}.json"), "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=1)
    # also print a compact summary
    print(f"[pattern {i}] req={rec['req_body_text'][:160]!r}")
    print(f"             resp={ (rec['resp_body_text'] or rec['resp_body_hex'])[:200]!r}")

def done():
    print(f"[dump_pattern] wrote {n['i']} pattern flows to {OUT}/pattern_*.json")
