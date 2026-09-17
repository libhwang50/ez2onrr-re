#!/usr/bin/env python3
"""High-frequency InGameCore poller: captures fresh CDN URLs, bundleCryptKey,
and dumps any in-memory decrypted EZFF chart. Downloads ciphertext via curl."""
import os, sys, time, json, subprocess, threading, signal
import frida

OUT_DIR = "extracted_charts/_live"

HEADERS = [
    "User-Agent: UnityPlayer/6000.0.78f1 (UnityWebRequest/1.0, libcurl/8.10.1-DEV)",
    "Accept: */*",
    "X-Unity-Version: 6000.0.78f1",
]

_LIVE = None
def _cleanup():
    if _LIVE:
        try: _LIVE.detach()
        except Exception: pass
def _sigterm(s, f):
    _cleanup(); os._exit(0)

def curl(url, outpath):
    try:
        r = subprocess.run(["curl", "-sS", "--compressed", "-o", outpath,
                            *[a for h in HEADERS for a in ("-H", h)], url],
                           timeout=60)
        if r.returncode == 0 and os.path.exists(outpath):
            sz = os.path.getsize(outpath)
            if sz > 0:
                print(f"    [curl OK] {outpath} ({sz:,} bytes)", flush=True)
                return sz
        print(f"    [curl FAIL] rc={r.returncode}", flush=True)
    except Exception as e:
        print(f"    [curl ERR] {e}", flush=True)
    return 0

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    signal.signal(signal.SIGTERM, _sigterm)
    dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
    global _LIVE
    _LIVE = dev.attach("Gadget")
    sc = _LIVE.create_script(open("../build/_poll_run.js").read())
    sc.load()
    print("[+] poller attached. Select a song in-game to trigger chart download...", flush=True)

    seen_urls = set()
    seen_keys = set()
    last_statics = None
    last_scan = 0.0
    done = {}

    try:
        while True:
            try:
                st = sc.exports_sync.state()
            except Exception as e:
                print("state err", e, flush=True)
                time.sleep(0.5)
                continue
            if st.get("error"):
                time.sleep(0.5); continue

            t = time.time()
            # report key when it appears
            bk = st.get("bundleCryptKey")
            if bk and bk not in seen_keys:
                seen_keys.add(bk)
                print(f"\n[+] bundleCryptKey captured: {bk}\n", flush=True)
                open(os.path.join(OUT_DIR, "bundleCryptKey.txt"), "a").write(
                    f"{time.time()} sol={st.get('sol')!r} key={bk}\n")

            # statics rotation detection
            stx = st.get("statics")
            if last_statics is None:
                last_statics = stx
                print(f"[*] statics svk..svr: { {k: (v[:16]+'..' if v else v) for k,v in stx.items()} }", flush=True)
            elif stx != last_statics:
                print(f"[+] STATICS ROTATED:\n  old={last_statics}\n  new={stx}", flush=True)
                last_statics = stx

            # new URLs -> download immediately
            for fld, ext in (("ezi_url", ".ezi"), ("ez_url", ".ez")):
                u = st.get(fld)
                if u and u not in seen_urls:
                    seen_urls.add(u)
                    print(f"\n[+] NEW {fld}: {u[:110]}...", flush=True)
                    fn = u.split("?")[0].split("/")[-1] or fld
                    out = os.path.join(OUT_DIR, f"{st.get('sol') or 'song'}_{fld}{ext}")
                    if fld not in done:
                        done[fld] = True
                        curl(u, out)

            # status line
            print(f"[{t:.0f}] sol={st.get('sol')!r} ready={st.get('ReadyToURL')} "
                  f"bk={'Y' if bk else '-'} svt={st.get('svt')!r} "
                  f"normal={st.get('normalNoteData')} long={st.get('longNoteData')} "
                  f"bpm={st.get('bpmNoteData')} instDic={st.get('instrumentDic')} "
                  f"pfi={st.get('patternFileInfo')}", flush=True)

            # periodic EZFF scan (every 3s)
            if t - last_scan > 3.0:
                last_scan = t
                try:
                    hits = sc.exports_sync.scan_ezff()
                except Exception as e:
                    print("scan err", e, flush=True)
                    hits = []
                if hits:
                    print(f"\n[!!!] EZFF FOUND: {len(hits)} hit(s)", flush=True)
                    for i, h in enumerate(hits):
                        fn = os.path.join(OUT_DIR, f"EZFF_{i}_{h['address']}.bin")
                        with open(fn, "wb") as f:
                            f.write(bytes.fromhex(h["hex"]))
                        print(f"    saved {h['len']:,} bytes -> {fn}", flush=True)

            time.sleep(0.15)
    except KeyboardInterrupt:
        print("\nstopped", flush=True)
    finally:
        _cleanup()

if __name__ == "__main__":
    main()
