#!/usr/bin/env python3
"""
mitmproxy addon: parse captured EZ2ON flows offline.

Usage:
    mitmdump -nr mitm_flows.mitm -s _parse_mitm.py

Extracts:
  * API responses (game1-play / game1-test99) containing bundleCryptKey /
    final_url_ez / final_url_ezi / CRYPT_KEY -> mitm_parsed/api_*.json
  * CDN response bodies (game1-cdn) -> mitm_parsed/cdn_*.bin  (ciphertext)
  * One-line JSON summary per HTTP flow -> mitm_parsed/flows.jsonl
"""
import json
import os
import re
from mitmproxy import http

OUT = os.path.join(os.getcwd(), "mitm_parsed")
os.makedirs(OUT, exist_ok=True)

API_HOSTS = ("game1-play.ez2game.co.kr", "game1-test99.ez2game.co.kr")
CDN_HOSTS = ("game1-cdn.ez2game.co.kr",)

FLOW_LOG = open(os.path.join(OUT, "flows.jsonl"), "w", encoding="utf-8")

_key_re = re.compile(r"(bundleCryptKey|CRYPT_KEY|AES_KEY|AES_IV)", re.I)
_api_counter = {"n": 0}
_cdn_counter = {"n": 0}


def _safe_path(url):
    # filename-safe id from the path
    p = url.split("?")[0].strip("/")
    p = re.sub(r"[^A-Za-z0-9_.-]", "_", p)
    return p[-120:] or "flow"


def response(flow: http.HTTPFlow):
    host = (flow.request.host or "").lower()
    req = flow.request
    resp = flow.response

    rec = {
        "host": host,
        "method": req.method,
        "path": req.path,
        "url": req.pretty_url[:400],
        "status": resp.status_code if resp else None,
        "ctype": (resp.headers.get("content-type", "") if resp else ""),
        "body_len": len(resp.content) if resp and resp.content else 0,
        "req_body": None,
    }

    # request body (may carry appid/keymode/levelmode/gamemode for the API)
    if req.content:
        try:
            rb = req.content.decode("utf-8", "ignore")
        except Exception:
            rb = req.content[:200].hex()
        rec["req_body"] = rb[:2000]

    body = None
    if resp and resp.content:
        body = bytes(resp.content)

    # --- API responses ---
    if host in API_HOSTS and body:
        try:
            text = body.decode("utf-8", "ignore")
        except Exception:
            text = ""
        if _key_re.search(text) or "final_url" in text or "musicList" in text:
            fn = os.path.join(OUT, f"api_{_api_counter['n']:03d}.json")
            _api_counter["n"] += 1
            with open(fn, "w", encoding="utf-8") as f:
                f.write(text)
            rec["saved"] = os.path.basename(fn)
            rec["has_key"] = bool(_key_re.search(text))

    # --- CDN responses (ciphertext) ---
    if host in CDN_HOSTS and body and body[:4] not in (b"<?xm", b"<Err"):
        fn = os.path.join(OUT, f"cdn_{_cdn_counter['n']:03d}_{_safe_path(req.path)}.bin")
        _cdn_counter["n"] += 1
        with open(fn, "wb") as f:
            f.write(body)
        rec["saved"] = os.path.basename(fn)

    FLOW_LOG.write(json.dumps(rec) + "\n")
    FLOW_LOG.flush()


def done():
    FLOW_LOG.close()
    print(f"[_parse_mitm] wrote {OUT}/ (api={_api_counter['n']}, cdn={_cdn_counter['n']})")
