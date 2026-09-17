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


# --- human-readable labels ---------------------------------------------------

LANE_LABEL = {4: '4K', 5: '5K', 6: '6K', 7: '7K', 8: '8K'}
DIFF_LABEL = {'1': 'EZ', '2': 'NM', '3': 'HD', '4': 'SHD'}
# The API's keymode is 1-based over the key modes. 1, 2 and 3 are confirmed (4K, 5K, 6K);
# 4+ is unobserved, so it is reported as-is rather than guessed.
KEYMODE_LABEL = {'1': '4K', '2': '5K', '3': '6K'}
LABELS_FILE = 'chart_labels.json'


def runtime_pattern(sc):
    """The chart the game has in play, from the request JSON it holds in memory.

    `InGameCore.patternFileInfo` is null by the time a capture runs, but the game keeps the
    `c2s_get_pattern_file` request as a UTF-16 string —
    `{"appid":...,"musicresourcename":"Rebind","keymode":"2","levelmode":"3",...}` —
    which is authoritative and needs no API capture. Scanning takes ~2 s.
    """
    try:
        found = sc.exports_sync.patternjson()
    except Exception:
        return None
    for s in (found or []):
        try:
            rec = json.loads(s)
        except Exception:
            continue
        if rec.get('musicresourcename'):
            return rec
    return None


def variant_from_name(ez_path):
    """(keymode, difficulty) taken ONLY from the chart's header name, or (None, None).

    The name encodes the variant (`4-shd`, `8-ez`, `5-nm`) and is the most direct source,
    but it is sometimes empty or `#PTMAKE`. Deliberately does not fall back to the lane
    count — that is a weaker signal and must not outrank the runtime.
    """
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from parse_chart import parse_ez, VARIANT_RE
        name = parse_ez(open(ez_path, 'rb').read()).header['name'] or ''
        m = VARIANT_RE.match(name)
        return (m.group(1) + 'K', m.group(2).upper()) if m else (None, None)
    except Exception:
        return None, None


def chart_variant(ez_path):
    """(keymode, difficulty, lane_count) read out of the chart itself.

    Key mode falls back to the playable lane count when the name does not carry it.
    """
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from parse_chart import parse_ez
        ch = parse_ez(open(ez_path, 'rb').read())
        return ch.keymode, ch.difficulty, ch.lane_count
    except Exception:
        return None, None, None


def label_for(ezi_url, root='.'):
    """Look up (song, keymode, levelmode, gamemode) for a chart by its .ezi URL.

    Populated from the API traffic by `chart_labels.py`; the game's own
    `patternFileInfo` is empty by the time a capture runs, so this is where the song name
    and difficulty come from.
    """
    path = os.path.join(root, LABELS_FILE)
    if not ezi_url or not os.path.exists(path):
        return None
    try:
        table = json.load(open(path))
    except Exception:
        return None
    return table.get(ezi_url.split('?')[0].split('/')[-1][:24])


def describe(snap, d, runtime=None):
    """One line naming the song and its mode/difficulty, plus a dict for ident.json.

    Source order: the game's own request JSON (authoritative), then the chart's header name
    (which encodes the variant), then the label cache from API captures, then the lane
    count for key mode.
    """
    runtime = runtime or {}
    lab = label_for(snap.get('ezi_url'), os.path.dirname(os.path.abspath(__file__))) or {}
    name_km, name_diff = variant_from_name(os.path.join(d, 'ez.ez'))
    lanes = chart_variant(os.path.join(d, 'ez.ez'))[2]
    file_km = name_km or LANE_LABEL.get(lanes)          # the chart file's own key mode
    rt_km = KEYMODE_LABEL.get(str(runtime.get('keymode')))
    rt_diff = DIFF_LABEL.get(str(runtime.get('levelmode')))

    # The runtime reflects whatever was playing when it was read, so only trust it when it
    # agrees with the chart file. Otherwise the lane count wins (a 4-lane chart is 4K
    # whatever the game was doing) and we say so rather than mixing the two.
    consistent = not (file_km and rt_km) or file_km == rt_km
    km = file_km or rt_km
    diff = name_diff or (rt_diff if consistent else None) or \
           DIFF_LABEL.get(str(lab.get('levelmode')))
    song = (runtime.get('musicresourcename') if consistent else None) \
        or lab.get('song') or song_name(snap)

    mismatch = ''
    if file_km and rt_km and file_km != rt_km:
        mismatch = ('chart is %s (%d lanes) but the game requested %s; the runtime '
                    'difficulty was ignored' % (file_km, lanes or 0, rt_km))
    bits = [b for b in (km, diff) if b]
    out = {'song': song, 'keymode': km, 'lanes': lanes, 'difficulty': diff,
           'keymodeFromChart': file_km, 'keymodeFromRuntime': rt_km,
           'levelmode': runtime.get('levelmode') or lab.get('levelmode'),
           'gamemode': runtime.get('gamemode') or lab.get('gamemode'),
           'labelSource': 'runtime' if (runtime and consistent) else 'chart',
           'labelMismatch': mismatch or None}
    text = '   song    : %s%s' % (song, ('  [%s]' % ' '.join(bits)) if bits else '')
    if runtime:
        text += '   (runtime keymode=%s levelmode=%s gamemode=%s)' % (
            runtime.get('keymode'), runtime.get('levelmode'), runtime.get('gamemode'))
    elif name_diff:
        text += "   (variant from the chart's header name)"
    elif lab:
        text += '   (difficulty from API levelmode=%s)' % lab.get('levelmode')
    else:
        text += '   (key mode from lane count; difficulty unknown)'
    if mismatch:
        text += '\n   !! label mismatch: %s' % mismatch
    return text, out


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


def settle(sc, timeout=15.0, interval=1.0):
    """Poll until the game has finished parsing the chart it just fetched.

    `ident()` is first readable as soon as the CDN URLs appear, which is before the
    chart is parsed — so an immediate snapshot reports lanes=[0,0,0,0] and dic=0.
    Returns the snapshot with the most parse progress seen before the timeout.

    Deliberately slow (1 Hz): the game has crashed twice during song load while this
    watcher was polling, and AGENTS.md warns about high-frequency in-process polling.
    The chart and keysounds are already on disk by this point, so this is only for the
    cross-check against the game's own parse.
    """
    deadline = time.time() + timeout
    best, best_score = None, -1
    while True:
        try:
            try:
                snap = sc.exports_sync.ident(True)      # with normalLanes
            except Exception:
                snap = sc.exports_sync.ident()           # older driver without the flag
            lanes = [x for x in (snap.get('normalLanes') or []) if isinstance(x, int) and x > 0]
            dic = snap.get('instrumentDicCount') or 0
            score = sum(lanes) + dic
            if score > best_score:
                best, best_score = snap, score
            if lanes and dic:
                return snap
        except Exception:
            pass
        if time.time() >= deadline:
            return best
        time.sleep(interval)


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
            if decrypt_chart.is_plaintext(body):
                pt, pair = body, '-'
            else:
                pt, pair = decrypt_chart.decrypt_named(body)
            if not decrypt_chart.plausible(pt):
                raise ValueError('plaintext is neither a chart nor an index')
            with open(os.path.join(d, "%s.%s" % (tag, ext)), "wb") as f:
                f.write(pt)
            print("   %-4s plaintext [%s]: %s" % (tag, pair, decrypt_chart.summarize(pt)))
        except Exception as e:
            print("   !! %s decrypt failed: %s  (cdn_*.bin kept for later)" % (tag, e))

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

    # 2) wait for the game to finish parsing, then snapshot the parsed state.
    #    The ident() taken on entry races the parse and reports zeros.
    settled = settle(sc)
    if settled:
        lanes = settled.get("normalLanes")
        print("   parsed  : lanes=%s  dic=%s  bpm=%s  measures=%s" % (
            lanes, settled.get("instrumentDicCount"),
            settled.get("bpmNoteDataCount"), settled.get("MeasureScaleDataCount")))
        if not lanes or not any(isinstance(x, int) and x > 0 for x in lanes):
            print("   !! chart not parsed within the settle window; ident.json may be early")
    else:
        print("   !! could not re-read ident; writing the entry-time snapshot")

    # name the song and its mode/difficulty
    try:
        rt = runtime_pattern(sc)
        text, label = describe(settled or snap, d, rt)
        print(text)
        base = settled or snap
        base['label'] = label
        with open(os.path.join(d, "ident.json"), "w") as f:
            json.dump(base, f, indent=1)
    except Exception as e:
        print("   !! labelling failed: %s" % e)

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
