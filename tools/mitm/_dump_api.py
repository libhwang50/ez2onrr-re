#!/usr/bin/env python3
"""Dump specific API response bodies (login, gameinfo, myinfo) to inspect."""
import json, os
from mitmproxy import http

OUT = os.path.join(os.getcwd(), "mitm_parsed")
os.makedirs(OUT, exist_ok=True)

TARGETS = ["c2s_login", "c2s_get_gameinfo", "c2s_get_myinfo"]

def response(flow: http.HTTPFlow):
    p = flow.request.path
    for t in TARGETS:
        if t in p:
            resp = flow.response
            body = bytes(resp.content) if resp else b""
            fn = os.path.join(OUT, f"{t}.bin")
            with open(fn, "wb") as f:
                f.write(body)
            # also try text
            try:
                txt = body.decode("utf-8", "ignore")
                with open(os.path.join(OUT, f"{t}.txt"), "w") as f:
                    f.write(txt)
            except Exception:
                pass
            print(f"[{t}] status={resp.status_code if resp else None} len={len(body)} "
                  f"head={body[:80].hex()} text={body[:120]!r}")
