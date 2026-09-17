#!/usr/bin/env python3
"""
dump_song.py — snapshot every song you enter, automatically.

Attaches to the running game's Frida Gadget and watches `InGameCore.instance`.
Each time a new chart is fetched it immediately (a) downloads the signed CDN
URLs while they are still valid, and (b) saves the in-memory chart buffers,
the keysound dictionary and the parsed note data.

Usage
-----
    python3 dump_song.py                # watch, ~2 Hz, output under extracted_charts/
    python3 dump_song.py --out dir --interval 0.4

Then just play songs; each one is captured on entry.  Safe: read-only memory
reads plus one HTTP GET per chart — no hooks, no guard pages.

Notes
-----
* CDN signed URLs expire after ~150 s, so they are fetched the moment they
  appear.  A 403 means the URL expired before we got to it.
* Both the byte-exact payload as served (`cdn_ez_*.bin`) and the decrypted
  plaintext (`ez.ez` / `ezi.ezi`) are written, so the archive is reproducible
  without re-visiting the CDN.
* The in-memory parse (`instrumentDic.json`, `*_chart.json`) is a cross-check on
  the decrypted files, not the source of truth.
"""
import argparse, json, os, re, sys, time, urllib.request, urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import decrypt_chart  # noqa: E402  (same directory)

HEADERS = {
    "User-Agent": "UnityPlayer/6000.0.78f1 (UnityWebRequest/1.0, libcurl/8.10.1-DEV)",
    "Accept": "*/*",
    "X-Unity-Version": "6000.0.78f1",
}
GADGET = "127.0.0.1:27042"


def fetch(url, timeout=30):
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def safe(name):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:80] or "song"


def song_name(snap):
    pats = snap.get("patterns") or []
    if pats:
        p = pats[0]
        parts = [p.get("musicresourcename") or "", p.get("keymode") or "",
                 p.get("levelmode") or "", p.get("gamemode") or ""]
        joined = "_".join(x for x in parts if x)
        if joined:
            return safe(joined)
    url = snap.get("ezi_url") or ""
    m = re.search(r"/fb_2/[0-9a-f]{2}/([0-9a-f]{8})", url)
    return "song_" + (m.group(1) if m else str(int(time.time())))


def capture(sc, snap, out_root):
    name = song_name(snap)
    d = os.path.join(out_root, name)
    os.makedirs(d, exist_ok=True)
    print("\n=== %s ===" % name)
    print("   ez_url  : %s" % (snap.get("ez_url") or "")[:80])
    print("   ezi_url : %s" % (snap.get("ezi_url") or "")[:80])
    print("   notes   : lanes=%s  dic=%s  bpm=%s  measures=%s" % (
        snap.get("normalLanes"), snap.get("instrumentDicCount"),
        snap.get("bpmNoteDataCount"), snap.get("MeasureScaleDataCount")))
    with open(os.path.join(d, "ident.json"), "w") as f:
        json.dump(snap, f, indent=1)

    # 1) the CDN payloads — grab them before the signed URL expires, then decrypt
    for field, tag, ext in (("ez_url", "ez", "ez"), ("ezi_url", "ezi", "ezi")):
        url = snap.get(field)
        if not url:
            continue
        try:
            body = fetch(url)
            fn = os.path.join(d, "cdn_%s_%d.bin" % (tag, len(body)))
            with open(fn, "wb") as f:
                f.write(body)
            print("   saved %-4s %7d bytes  <- %s" % (tag, len(body), field))
        except urllib.error.HTTPError as e:
            print("   !! %s fetch failed: HTTP %s (signed URL likely expired)" % (tag, e.code))
            continue
        except Exception as e:
            print("   !! %s fetch failed: %s" % (tag, e))
            continue

        # decrypt the payload we just archived
        try:
            pt = body if decrypt_chart.is_plaintext(body) else decrypt_chart.decrypt(body)
            with open(os.path.join(d, "%s.%s" % (tag, ext)), "wb") as f:
                f.write(pt)
            print("   %-4s plaintext: %s" % (tag, decrypt_chart.summarize(pt)))
        except Exception as e:
            print("   !! %s decrypt failed: %s" % (tag, e))

    # 2) the in-memory buffers the game actually decrypts
    try:
        rus = sc.exports_sync.da_rus_full()
        if rus:
            for k, hexv in rus.items():
                if not hexv:
                    continue
                with open(os.path.join(d, "mem_%s.bin" % k), "wb") as f:
                    f.write(bytes.fromhex(hexv))
            print("   saved mem_rjl/rjm/rjn (in-memory buffers + key)")
    except Exception as e:
        print("   !! da.rus read failed: %s" % e)

    # 3) the decrypted, parsed chart as the game holds it
    try:
        dic = sc.exports_sync.instrument_dic()
        with open(os.path.join(d, "instrumentDic.json"), "w") as f:
            json.dump(dic, f)
        print("   saved instrumentDic.json (%d entries)" % len(dic))
    except Exception as e:
        print("   !! instrumentDic read failed: %s" % e)
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="extracted_charts")
    ap.add_argument("--interval", type=float, default=0.5)
    ap.add_argument("--gadget", default=GADGET)
    a = ap.parse_args()

    import frida
    dev = frida.get_device_manager().add_remote_device(a.gadget)
    ses = dev.attach("Gadget")
    driver = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "tools", "build", "_dumpsong_run.js")
    if not os.path.exists(driver):
        sys.exit("missing %s — run: bash tools/il2cpp/build_run.sh" % driver)
    sc = ses.create_script(open(driver).read())
    sc.load()
    print("attached to gadget; watching for songs (Ctrl-C to stop)")

    seen, last_note = set(), 0.0
    while True:
        try:
            snap = sc.exports_sync.ident()
        except Exception:
            time.sleep(1.0)
            continue
        url = snap.get("ezi_url")
        if url and url not in seen:
            seen.add(url)
            try:
                capture(sc, snap, a.out)
            except Exception as e:
                print("   !! capture error: %s" % e)
        time.sleep(a.interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nstopped")
