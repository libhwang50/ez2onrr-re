#!/usr/bin/env python3
"""
EZ2ON REBOOT: R - In-Process Chart/Audio Downloader

The CDN (game1-cdn.ez2game.co.kr) serves charts/keysounds over CloudFront signed
URLs. A plain host-side request (curl / urllib) gets HTTP 403 "Access Denied" even
though the URL is valid and the requester shares the game's exact network namespace
(same egress IP). The game itself downloads these fine, so the request must carry an
attribute the CDN expects that our host client does not.

Fix: perform the HTTP GET from *inside* the game process (EZ2ON.exe / Frida Gadget)
using its own WinHTTP stack, then stream the response bytes back over the Frida RPC
channel. This is read-only (NativeFunction export resolution, no code patched), so it
stays under the zero-hook anti-cheat threshold.

Usage:
    .venv/bin/python download_inproc.py            # capture fresh URLs from RAM, download both
    .venv/bin/python download_inproc.py --max 3    # stop after N files
"""

import os
import re
import sys
import time
import threading
import signal
import base64
import frida

OUTPUT_DIR = "extracted_charts/_inproc"

# Track the live session so a SIGTERM (e.g. `timeout`) can detach cleanly.
# SIGTERM does NOT run Python finally blocks, so without this an agent is left
# resident and wedges the gadget's message loop.
_LIVE_SESSION = None

def _cleanup():
    if _LIVE_SESSION is not None:
        try:
            _LIVE_SESSION.detach()
        except Exception:
            pass

def _on_sigterm(signum, frame):
    _cleanup()
    os._exit(0)

def get_frida_script():
    src = open("harvest_chart.py").read()
    fjs = re.search(r"FRIDA_JS_SCRIPT = \"\"\"(.*?)\"\"\"", src, re.S).group(1)
    wjs = open(os.path.join(os.path.dirname(__file__), "winhttp_download.js")).read()
    return fjs + "\n" + wjs

def main():
    max_files = int(os.environ.get("MAX_FILES", "2"))
    argv = sys.argv[1:]
    for a in argv:
        if a.startswith("--max="):
            max_files = int(a.split("=", 1)[1])

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print("=" * 65, flush=True)
    print("  EZ2ON REBOOT: R - In-Process (WinHTTP) Downloader", flush=True)
    print("  Downloads from inside EZ2ON.exe -> bypasses CDN 403.", flush=True)
    print("=" * 65, flush=True)

    print("[*] Connecting to Frida Gadget at 127.0.0.1:27042...", flush=True)
    global _LIVE_SESSION
    signal.signal(signal.SIGTERM, _on_sigterm)
    dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
    session = _with_timeout(lambda: dev.attach("Gadget"), 20.0, "attach")
    _LIVE_SESSION = session
    print("[+] Successfully connected to Frida Gadget!", flush=True)
    try:
        # create_script + load block until the agent acks. If the game is PAUSED,
        # the gadget's message thread is suspended and this hangs. Bound it and
        # tell the user clearly instead of hanging forever.
        script = _with_timeout(lambda: session.create_script(get_frida_script()), 20.0)
        _with_timeout(script.load, 20.0)
    except TimeoutError:
        print("[!] Timed out loading the Frida agent. The game is likely PAUSED; "
              "resume play or restart the game and try again.")
        try:
            session.detach()
        except Exception:
            pass
        sys.exit(2)

    # Surface the agent's send() step-logs (WinHTTP progress) so we can see
    # exactly where a request stalls.
    def _on_msg(message, data):
        payload = message.get("payload") if isinstance(message, dict) else None
        if payload is not None:
            print("    <agent> " + str(payload), flush=True)
    script.on("message", _on_msg)

    print("[*] Waiting for InGameCore to report an active song...", flush=True)
    print("[*] Launch a song / enter gameplay in EZ2ON...", flush=True)

    seen = set()
    saved = 0
    try:
        while saved < max_files:
            try:
                res = script.exports_sync.check_in_game_core()
            except Exception:
                time.sleep(0.4)
                continue
            if res.get("status") != "active":
                time.sleep(0.4)
                continue

            for field in ("ezi_url", "ez_url"):
                url = res.get(field)
                if not url or url in seen:
                    continue
                seen.add(url)
                fn = os.path.basename(url.split("?")[0]) or field
                print(f"\n[+] {field}: {fn}")
                try:
                    r = _with_timeout(lambda: script.exports_sync.download_win_http(url), 60.0, "download " + field)
                except TimeoutError as te:
                    print(f"    [HANG] {te} -- agent still resident; skipping to next URL")
                    continue
                except Exception as e:
                    print(f"[!] RPC error: {e}")
                    continue
                if r.get("ok"):
                    data = base64.b64decode(r["bodyBase64"])
                    out = os.path.join(OUTPUT_DIR, fn)
                    with open(out, "wb") as f:
                        f.write(data)
                    print(f"    [OK] status={r['status']} bytes={len(data):,} -> {out}")
                    saved += 1
                else:
                    print(f"    [FAIL] {r.get('err', 'unknown')[:200]}")
            time.sleep(0.4)
        print(f"\n[+] Done. Saved {saved} file(s) in {OUTPUT_DIR}/")
    except KeyboardInterrupt:
        print("\n[+] Stopped by user.")
    finally:
        _timed_detach(session)

def _timed_detach(s, seconds=10):
    """Detach, but never hang forever. If the agent is stuck mid-native-call,
    detach can block; force-exit so our process always returns (the gadget
    itself needs a game restart to clear a resident-stuck agent)."""
    class _T(threading.Thread):
        def run(self):
            try:
                s.detach()
            except Exception:
                pass
            self.done = True
    t = _T(); t.daemon = True; t.start()
    t.join(seconds)
    if not getattr(t, "done", False):
        print("[!] detach stuck (agent mid-call) -- forcing exit")
        os._exit(0)

def _with_timeout(fn, seconds, label="op"):
    """Run a blocking Frida call with a timeout; raise TimeoutError if it hangs."""
    result = {"error": None, "value": None}
    def target():
        try:
            result["value"] = fn()
        except Exception as e:
            result["error"] = e
    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(seconds)
    if t.is_alive():
        raise TimeoutError(f"{label} timed out after {seconds}s (game likely paused)")
    if result["error"]:
        raise result["error"]
    return result["value"]

if __name__ == "__main__":
    main()
