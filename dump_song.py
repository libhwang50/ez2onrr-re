#!/usr/bin/env python3
"""
dump_song.py — snapshot every song you enter, automatically.

Attaches to the running game's Frida Gadget and watches `InGameCore.instance`.
Each time a new chart is fetched it immediately (a) downloads the signed CDN
URLs while they are still valid, and (b) saves the in-memory chart buffers,
the keysound dictionary and the parsed note data.

Usage
-----
    python3 dump_song.py                # watch, ~1 Hz, output under extracted_charts/
    python3 dump_song.py --out dir --interval 0.4
    python3 dump_song.py --read-instrument-dic   # opt into the risky cross-check read
    python3 dump_song.py --no-patternjson        # skip the in-memory label sweep (diagnostic)

Then just play songs; each one is captured on entry.  Read-only memory reads
plus one HTTP GET per chart — no hooks, no guard pages.

Where the reads run, and how they fail
--------------------------------------
Reads run on **Frida's own thread**, via `Il2Cpp.perform` alone.  The only thing
that genuinely needs the game's main thread is a call into the OS crypto provider
(Wine/CNG thread affinity), and this tool does no crypto.  Getting onto that
thread means hijacking it with `Process.runOnThread`, and that has livelocked it:
the main thread spins at 100% CPU, the gadget's message loop wedges so the RPC
never returns, and the game is left frozen.  It is not the managed invocations —
the hang was caught inside `daRusFull()`, which invokes nothing at all.
`--on-main` restores the hijack for anyone who needs a real crypto call.

When a read cannot go on it does **not** raise a clean error.  Three terminal
modes, all of which stop the watch after `WEDGE_LIMIT` consecutive failed polls:

* **the main thread is wedged** — spinning, gadget unresponsive, the call never
  returns.  Bounded by `RPC_TIMEOUT` so this reports instead of hanging forever,
  which is how it used to present;
* **the main thread has exited** while the process lingers — the window keeps
  showing its last frame and Steam still counts the game as running, but reads
  fail with `failed to run on thread` / `couldn't collect attached threads`;
* **the Frida script is unloaded** (the gadget tearing it down, or the host
  process going away) — reads fail with `script has been destroyed`.

A capture interrupted this way still writes `ident.json` (and an `incomplete`
list) from what it has, then stops the watch.  A failed *first* read is checked
at startup, because the usual cause is not the game you just launched: a crashed
game's *husk* keeps the gadget's TCP port (127.0.0.1:27042) bound, so a relaunched
game's gadget cannot listen and the attach lands on the dead process.  Kill the
leftover before relaunching.

`--no-patternjson` skips the `rw-` range sweep that reads the in-play request
JSON out of memory and takes the label from `chart_labels.json` instead.

Notes
-----
* CDN signed URLs expire after ~150 s, so they are fetched the moment they
  appear.  A 403 means the URL expired before we got to it.
* Both the byte-exact payload as served (`cdn_ez_*.bin`) and the decrypted
  plaintext (`ez.ez` / `ezi.ezi`) are written, so the archive is reproducible
  without re-visiting the CDN.
* The in-memory parse (`instrumentDic.json`) is a cross-check on the decrypted
  files, not the source of truth, and is **off by default**: walking the
  dictionary is ~4 managed invocations per entry (~8,000 for Ultimatum's 2,014)
  and the bridge holds the enumerator and its boxed keys as raw pointers the
  IL2CPP GC is never told about, so a GC mid-loop frees them and the next invoke
  touches freed memory.  `ezi.ezi` already carries the same mapping.  Use
  `--read-instrument-dic` when you want the cross-check.  (This was originally
  added while chasing the freezes, on the theory that it was the cause.  It was
  not — the hang was caught inside `daRusFull()`, which invokes nothing — but the
  unpacked-pointer risk is real, so it stays opt-in.)
* The output directory is decided by the *chart's own* identity, not only by the
  runtime label: the game updates `ez_url`/`ezi_url` in stages, so a snapshot
  taken mid-transition can pair the old label with the new chart.  Writing that
  eagerly previously overwrote a real capture with the wrong chart.  Such a
  snapshot now goes to `<name>_mismatch/` instead.
"""
import argparse, atexit, json, os, re, signal, sys, threading, time, urllib.request, urllib.error

# Track the live Frida session so SIGTERM (e.g. `timeout`), SIGINT and normal exit all
# detach it. SIGTERM does NOT run Python finally blocks, so without this the agent is left
# resident and wedges the gadget's message loop — which has taken the game down.
_LIVE_SESSION = None


def _detach(*_a):
    global _LIVE_SESSION
    if _LIVE_SESSION is not None:
        try:
            _LIVE_SESSION.detach()
        except Exception:
            pass
        _LIVE_SESSION = None


def _install_teardown():
    def bye(*_a):
        _detach()
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:
            pass
        os._exit(0)

    atexit.register(_detach)
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        try:
            signal.signal(sig, bye)
        except Exception:
            pass

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
# The API's keymode is 1-based over the key modes: 1->4K, 2->5K, 3->6K, 4->8K (all four
# confirmed). 7K is unobserved (course-only), so any other value is reported as-is rather
# than guessed.
KEYMODE_LABEL = {'1': '4K', '2': '5K', '3': '6K', '4': '8K'}
LABELS_FILE = 'chart_labels.json'


def runtime_pattern(sc):
    """The chart the game has in play, from the request JSON it holds in memory.

    `InGameCore.patternFileInfo` is null by the time a capture runs, but the game keeps the
    `c2s_get_pattern_file` request as a UTF-16 string —
    `{"appid":...,"musicresourcename":"Rebind","keymode":"2","levelmode":"3",...}` —
    which is authoritative and needs no API capture. Scanning takes ~2 s.
    """
    try:
        fn = getattr(sc.exports_sync, 'patternjson', None)
        if fn is None:
            print('   !! driver has no patternjson(); cannot read the runtime label', flush=True)
            return None
        found = fn()
    except Exception as e:
        print('   !! patternjson failed: %s' % e, flush=True)
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


def chart_identity(ez_bytes):
    """Same as `chart_variant` but for a payload already in memory."""
    if not ez_bytes:
        return None, None, None
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from parse_chart import parse_ez
        ch = parse_ez(ez_bytes)
        return ch.keymode, ch.difficulty, ch.lane_count
    except Exception:
        return None, None, None


# --- read-path liveness -----------------------------------------------------
# Every managed read runs on the game's main thread (see tools/il2cpp/_dumpsong.js):
# `Il2Cpp.perform` + `Process.runOnThread`.  When that thread dies the process can linger
# with its worker threads, the window keeps showing its last frame, and Steam still counts
# the game as running — but every read fails.  The Frida script itself can also be torn down
# (the gadget unloading it, or the host process going away), which reports differently.  In
# both cases there is nothing left to capture, so the watch stops instead of polling a
# corpse and writing half-empty snapshots that look successful.
WEDGE_MARKERS = (
    'failed to run on thread',
    "couldn't collect attached threads",
    'script has been destroyed',
    'script is destroyed',
    'process has been destroyed',
    'process is gone',
    'session is detached',
    'the connection is closed',
)
WEDGE_LIMIT = 3  # consecutive failed polls before the game is declared gone
RPC_TIMEOUT = 20.0  # seconds a single driver call may block before the game is called wedged


class GameWedged(Exception):
    """The read path is gone (main thread exited, script unloaded, host process dead)."""


def is_wedged(exc):
    msg = str(exc)
    return any(m in msg for m in WEDGE_MARKERS)


def rpc(sc, name, *args, timeout=RPC_TIMEOUT):
    """Call a driver export, with a timeout.

    A read that never returns is the worst failure mode this tool has: the game's main thread
    is wedged (spinning at 100% CPU, gadget unresponsive) and a plain call would block on a
    futex forever, with no output, which is exactly how it presented.  The call therefore runs
    on a daemon thread so the wait can be bounded; a timeout is reported as GameWedged.
    """
    fn = getattr(sc.exports_sync, name, None)
    if fn is None:
        raise AttributeError('driver has no %s()' % name)
    box, done = {}, threading.Event()

    def run():
        try:
            box['v'] = fn(*args)
        except BaseException as e:      # forwarded to the caller, whatever it is
            box['e'] = e
        finally:
            done.set()

    threading.Thread(target=run, daemon=True).start()
    if not done.wait(timeout):
        raise GameWedged('no response to %s() within %gs' % (name, timeout))
    if 'e' in box:
        e = box['e']
        if is_wedged(e):
            raise GameWedged(str(e)) from None
        raise e
    return box.get('v')


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

    # enrich with the game's metadata table (title, composer), when it resolves
    meta = {}
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import song_meta
        rec = song_meta.by_name(song)
        if rec:
            meta = {'title': song_meta.title(rec) or song,
                    'composer': rec.get('Composer') or None,
                    'musicId': rec.get('id'),
                    'metaNameKr': rec.get('KorName'), 'metaNameEn': rec.get('EngName'),
                    'metaNameJp': rec.get('JapName')}
    except Exception:
        pass

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
    out.update(meta)
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
    if meta:
        text += '\n   meta    : %s%s%s' % (
            meta.get('title') or song,
            ('  —  ' + meta['composer']) if meta.get('composer') else '',
            ('   (music id %s)' % meta['musicId']) if meta.get('musicId') else '')
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


def safe_dir(name):
    """Filesystem-friendly directory name: lowercase, alphanumerics and - _ . only."""
    s = re.sub(r"[^A-Za-z0-9_.-]", "_", str(name)).strip("._").lower()
    return s[:80] or "song"


def capture_name(rt, snap, name_by='variant'):
    """Relative directory path for a capture, under the charts root.

    `variant` (default) nests key mode and difficulty — `destr0yer/5k/hd` — so each variant
    of a song keeps its own capture instead of replacing whichever was there. The chart
    differs by mode and difficulty (only the note *assignment* does, but it is still a
    different file), so separating them is the safe default.

    `title` drops the nesting and merges every variant into one directory — fine when you only
    want the song once, since one chart renders the whole song. `id` uses the numeric music id
    in place of the name, keeping the nesting.

    Falls back to `song_<hash>` when the runtime label is unavailable, which is the one case
    where the song is unknown.
    """
    resource = (rt or {}).get('musicresourcename')
    if resource:
        if name_by == 'id':
            try:
                sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
                import song_meta
                rec = song_meta.by_name(resource)
                if rec and rec.get('id'):
                    resource = str(rec['id'])
            except Exception:
                pass
        title = safe_dir(resource)
        if name_by == 'title':
            return title
        km = (KEYMODE_LABEL.get(str(rt.get('keymode'))) or '').lower()
        diff = (DIFF_LABEL.get(str(rt.get('levelmode'))) or '').lower()
        return os.path.join(*([title] + [p for p in (km, diff) if p]))
    return song_name(snap)


def label_cache_as_runtime(snap):
    """Build an `rt`-shaped label from the API cache, without touching the game.

    Used by `--no-patternjson`, which skips the `rw-` range sweep that normally reads the
    game's `c2s_get_pattern_file` request JSON out of memory.  The cache is filled in from
    mitmproxy captures by `chart_labels.py`, so it only covers songs already seen — when it
    misses, naming falls back to `song_<hash>`.
    """
    lab = label_for(snap.get('ezi_url'), os.path.dirname(os.path.abspath(__file__))) or {}
    if not lab.get('song'):
        return None
    return {'musicresourcename': lab['song'], 'keymode': lab.get('keymode'),
            'levelmode': lab.get('levelmode'), 'gamemode': lab.get('gamemode')}


def settle(sc, timeout=20.0, interval=1.0):
    """Wait for the game to finish parsing, then read the parsed state once.

    Two phases, deliberately. Computing `normalLanes` means invoking `get_Item`/`get_Count`
    on `normalNoteData`'s inner lists; doing that while the game is still building them
    produced a 5-entry `normalLanes` for a 4-lane chart — a snapshot taken mid-mutation, and
    exactly the kind of access that has taken the game down.

    Phase 1 polls only the cheap counts (no per-lane invocations) until they stop changing;
    phase 2 asks for the lanes exactly once. On timeout the cheap snapshot is returned, so
    a failure here still yields the buffer counts.
    """
    deadline = time.time() + timeout
    last, best = None, None
    while True:
        try:
            snap = rpc(sc, 'ident')                 # cheap: no lane invocations
            best = snap
        except GameWedged:
            raise
        except Exception:
            snap = None
        if snap:
            counts = (snap.get('instrumentDicCount'), snap.get('normalNoteDataCount'))
            if all(isinstance(c, int) and c > 0 for c in counts):
                if counts == last:
                    try:
                        return rpc(sc, 'ident', True)   # read the lanes once
                    except GameWedged:
                        raise
                    except Exception:
                        return snap
                last = counts
        if time.time() >= deadline:
            return best
        time.sleep(interval)


def capture(sc, snap, out_root, name_by='title', read_dic=False, use_patternjson=True):
    t0 = time.time()

    def mark(label, extra=''):
        # Timestamped, flushed: if the game dies mid-capture this says exactly where.
        print('   [+%5.1fs] %s%s' % (time.time() - t0, label, extra), flush=True)

    # Read the runtime identity FIRST, so the directory can be named after the song rather
    # than after a URL hash.  `patternjson` sweeps every `rw-` range for the request JSON;
    # `--no-patternjson` skips that sweep and takes the label from the API cache instead,
    # which is the switch used to test whether the sweep is what the game dies on.
    mark('reading the runtime label')
    if use_patternjson:
        rt = runtime_pattern(sc)
    else:
        rt = label_cache_as_runtime(snap)
        print('   note    : --no-patternjson; label from the API cache%s'
              % ('' if rt else ' (miss, will fall back to the URL hash)'))

    name = capture_name(rt, snap, name_by)
    d = os.path.join(out_root, name)
    existing = None
    if os.path.exists(os.path.join(d, 'ident.json')):
        try:
            existing = (json.load(open(os.path.join(d, 'ident.json'))) or {}).get('label') or {}
        except Exception:
            existing = {}
    incomplete = []   # artifact names we could not write; printed at the end

    print("\n=== %s ===" % name)
    if existing:
        old = ' '.join(x for x in (existing.get('keymode'), existing.get('difficulty')) if x)
        new = ' '.join(x for x in (KEYMODE_LABEL.get(str((rt or {}).get('keymode'))),
                                   DIFF_LABEL.get(str((rt or {}).get('levelmode')))) if x)
        print("   note    : replacing an existing capture%s"
              % ((' of %s with %s' % (old or '?', new or '?')) if old or new else ''))
    print("   ez_url  : %s" % (snap.get("ez_url") or "")[:80])
    print("   ezi_url : %s" % (snap.get("ezi_url") or "")[:80])
    print("   notes   : lanes=%s  dic=%s  bpm=%s  measures=%s" % (
        snap.get("normalLanes"), snap.get("instrumentDicCount"),
        snap.get("bpmNoteDataCount"), snap.get("MeasureScaleDataCount")))

    # 1) the CDN payloads — grab them before the signed URL expires, then decrypt.  Both
    #    are decrypted in memory before anything is written, because the chart's own
    #    identity decides the output directory: the game updates ez_url/ezi_url in stages, so
    #    a snapshot taken mid-transition can pair the old runtime label with the new chart.
    #    Writing that eagerly is what overwrote Ultimatum's real 5K SHD chart with a 4K one.
    payloads = []
    for field, tag, ext in (("ez_url", "ez", "ez"), ("ezi_url", "ezi", "ezi")):
        url = snap.get(field)
        if not url:
            continue
        try:
            body = fetch(url)
        except urllib.error.HTTPError as e:
            print("   !! %s fetch failed: HTTP %s (signed URL likely expired)" % (tag, e.code))
            incomplete.append("cdn_%s_*.bin" % tag)
            continue
        except Exception as e:
            print("   !! %s fetch failed: %s" % (tag, e))
            incomplete.append("cdn_%s_*.bin" % tag)
            continue
        try:
            if decrypt_chart.is_plaintext(body):
                pt, pair = body, '-'
            else:
                pt, pair = decrypt_chart.decrypt_named(body)
            if not decrypt_chart.plausible(pt):
                raise ValueError('plaintext is neither a chart nor an index')
        except Exception as e:
            print("   !! %s decrypt failed: %s  (cdn_*.bin kept for later)" % (tag, e))
            incomplete.append("%s.%s" % (tag, ext))
            payloads.append((tag, ext, body, None, None))
            continue
        payloads.append((tag, ext, body, pt, pair))

    # If the chart disagrees with the runtime label and a capture is already there, keep this
    # one aside rather than overwriting the real one.
    ez_pt = next((pt for tag, _e, _b, pt, _p in payloads if tag == "ez" and pt), None)
    chart_km, _chart_diff, chart_lanes = chart_identity(ez_pt)
    rt_km = KEYMODE_LABEL.get(str((rt or {}).get('keymode')))
    if ez_pt is not None and rt_km and chart_km and chart_km != rt_km and existing:
        d = os.path.join(out_root, name + '_mismatch')
        print("   !! chart is %s (%s lanes) but the runtime label says %s; keeping it in %s "
              "instead of overwriting" % (chart_km, chart_lanes, rt_km,
                                           os.path.relpath(d, out_root)))
        existing = None
    os.makedirs(d, exist_ok=True)

    for tag, ext, body, pt, pair in payloads:
        with open(os.path.join(d, "cdn_%s_%d.bin" % (tag, len(body))), "wb") as f:
            f.write(body)
        print("   saved %-4s %7d bytes  <- %s_url" % (tag, len(body), tag))
        if pt is None:
            continue
        with open(os.path.join(d, "%s.%s" % (tag, ext)), "wb") as f:
            f.write(pt)
        print("   %-4s plaintext [%s]: %s" % (tag, pair, decrypt_chart.summarize(pt)))

    # 2) the in-memory buffers the game actually decrypts
    wedged = False
    mark('reading da.rus buffers')
    try:
        rus = rpc(sc, 'da_rus_full')
        if rus:
            for k, hexv in rus.items():
                if not hexv:
                    continue
                with open(os.path.join(d, "mem_%s.bin" % k), "wb") as f:
                    f.write(bytes.fromhex(hexv))
            print("   saved mem_rjl/rjm/rjn (in-memory buffers + key)")
    except GameWedged as e:
        wedged = True
        print("   !! read path is gone (%s)" % e)
        incomplete.append('mem_*')
    except Exception as e:
        print("   !! da.rus read failed: %s" % e)
        incomplete.append('mem_*')

    # 3) wait for the game to finish parsing, then snapshot the parsed state.
    #    The ident() taken on entry races the parse and reports zeros.
    settled = None
    if not wedged:
        mark('waiting for the game to finish parsing')
        try:
            settled = settle(sc)
        except GameWedged as e:
            wedged = True
            print("   !! read path is gone (%s)" % e)
        except Exception as e:
            print("   !! settle failed: %s" % e)
    if settled:
        lanes = settled.get("normalLanes")
        print("   parsed  : lanes=%s  dic=%s  bpm=%s  measures=%s" % (
            lanes, settled.get("instrumentDicCount"),
            settled.get("bpmNoteDataCount"), settled.get("MeasureScaleDataCount")))
        if not lanes or not any(isinstance(x, int) and x > 0 for x in lanes):
            print("   !! chart not parsed within the settle window; ident.json may be early")
    else:
        print("   !! could not re-read ident; writing the entry-time snapshot")

    # name the song and its mode/difficulty.  Pure Python, so it still works when the game
    # is gone — the entry-time snapshot plus the decrypted chart are enough to label it.
    try:
        text, label = describe(settled or snap, d, rt)
        print(text)
        base = settled or snap
        base['label'] = label
        if incomplete or wedged:
            base['incomplete'] = list(incomplete)
        with open(os.path.join(d, "ident.json"), "w") as f:
            json.dump(base, f, indent=1)
    except Exception as e:
        print("   !! labelling failed: %s" % e)

    # 4) the decrypted, parsed chart as the game holds it.  OFF by default.  This is not
    #    the freeze cause it was once taken for — the hang was caught in daRusFull(), which
    #    invokes nothing — but walking a Dictionary with get_Keys/GetEnumerator/MoveNext/
    #    get_Current/get_Item is ~4 managed invocations per entry (~8,000 for Ultimatum's
    #    2,014), and the bridge holds the enumerator and its boxed keys as raw pointers the
    #    IL2CPP GC is never told about.  A GC mid-loop frees them and the next invoke touches
    #    freed memory.  It is only a cross-check anyway: `ezi.ezi` carries the same mapping.
    if read_dic and not wedged:
        mark('reading instrumentDic')
        try:
            dic = rpc(sc, 'instrument_dic')
            with open(os.path.join(d, "instrumentDic.json"), "w") as f:
                json.dump(dic, f)
            print("   saved instrumentDic.json (%d entries)" % len(dic))
        except GameWedged as e:
            wedged = True
            print("   !! read path is gone (%s)" % e)
            incomplete.append('instrumentDic.json')
        except Exception as e:
            print("   !! instrumentDic read failed: %s" % e)
            incomplete.append('instrumentDic.json')

    if wedged:
        mark('capture ABORTED')
        print("   !! the read path is gone (main thread exited, or the Frida script was\n"
              "      unloaded); no further read can succeed. Restart the game, then the dumper.")
    elif incomplete:
        mark('capture complete (incomplete)')
        print("   !! missing: %s" % ', '.join(incomplete))
    else:
        mark('capture complete')
    if not read_dic:
        print("   note    : instrumentDic.json skipped (--read-instrument-dic to include; "
              "ezi.ezi has the same mapping)")
    return d, wedged


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="extracted_charts")
    ap.add_argument("--interval", type=float, default=1.0,
                    help="watch poll interval in seconds (default 1.0; the signed URL lives "
                         "~150 s so there is no need to poll fast)")
    ap.add_argument("--name-by", choices=('variant', 'title', 'id'), default='variant',
                    help="variant (default): <song>_<keymode>_<difficulty> so each mode and "
                         "difficulty keeps its own capture; title: just the song, merging "
                         "variants; id: the numeric music id plus the variant")
    ap.add_argument(
        "--no-patternjson",
        action="store_true",
        help="skip the rw- range sweep that reads the in-play request JSON out of memory, "
             "and take the song/mode/difficulty from chart_labels.json instead. Diagnostic: "
             "that sweep is the only target-process call between the entry snapshot and the "
             "next read, so skipping it separates it from the managed reads.",
    )
    ap.add_argument(
        "--on-main",
        action="store_true",
        help="run reads on the game's main thread by hijacking it with Frida's "
             "Process.runOnThread.  Only needed for a call into the OS crypto provider; off "
             "by default because the hijack has livelocked that thread under Proton (it "
             "spins at 100%% and the gadget wedges, so reads never return).",
    )
    ap.add_argument("--gadget", default=GADGET)
    ap.add_argument(
        "--read-instrument-dic",
        action="store_true",
        help="also walk the game's instrumentDic through managed invocations and save it "
             "as a cross-check on the decrypted .ezi. Off by default: it is ~4 managed "
             "invocations per entry, which is the riskiest read this tool does, and the "
             ".ezi already carries the same mapping.",
    )
    a = ap.parse_args()

    import frida
    dev = frida.get_device_manager().add_remote_device(a.gadget)
    ses = dev.attach("Gadget")
    global _LIVE_SESSION
    _LIVE_SESSION = ses
    _install_teardown()
    try:
        sys.stdout.reconfigure(line_buffering=True)   # unbuffered logs under redirection
    except Exception:
        pass
    driver = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "tools", "build", "_dumpsong_run.js")
    if not os.path.exists(driver):
        sys.exit("missing %s — run: bash tools/il2cpp/build_run.sh" % driver)
    sc = ses.create_script(open(driver).read())
    sc.load()

    # Reads run on Frida's own thread unless --on-main; see the driver's `read`.  Set it
    # before the health check so that check exercises the path we will actually use.
    if getattr(sc.exports_sync, 'set_on_main', None) is not None:
        sc.exports_sync.set_on_main(bool(a.on_main))
        print('reads on: %s' % ("the game's main thread (--on-main)" if a.on_main
                                else "Frida's own thread"))
    else:
        print('note: driver predates setOnMain(); reads go wherever it puts them')

    seen = set()
    probe = getattr(sc.exports_sync, 'probe', None)
    if probe is None:
        print('note: driver has no probe(); falling back to the heavy ident() poll')
    else:
        # Health check.  A dead read path on the very first read almost always means we
        # attached to a *leftover* game process: when a crashed game's main thread exits
        # while the process lingers, that husk keeps the gadget's TCP port bound
        # (127.0.0.1:27042), so a relaunched game's gadget cannot listen and the attach
        # lands on the corpse instead.
        try:
            rpc(sc, 'probe')
        except GameWedged as e:
            sys.exit("the gadget is not answering reads (%s).\n"
                     "This usually means a previous game process is still alive and holding\n"
                     "port 27042:  pgrep -af EZ2ON.exe\n"
                     "Kill any leftover, relaunch the game, then retry." % e)
    print("attached to gadget; watching for songs (Ctrl-C to stop)")

    wedges = 0
    while True:
        try:
            # probe() is ~3x cheaper than ident(): three field reads instead of reflecting over
            # patternFileInfo, reading the da.rus buffers and counting five lists. The full
            # snapshot is only needed once a song is actually being captured.
            snap = rpc(sc, 'probe') if probe is not None else rpc(sc, 'ident')
            wedges = 0
        except GameWedged as e:
            # Every read goes through the game's main thread and its Frida script, so a
            # failure here means one of them is gone. A single one can be transient; a run
            # cannot.
            wedges += 1
            print('   !! game read failed (%s) [%d/%d]' % (e, wedges, WEDGE_LIMIT), flush=True)
            if wedges >= WEDGE_LIMIT:
                print("\nthe read path is gone. The game may still be listed as running and\n"
                      "its window may still show the last frame, but nothing can be read from\n"
                      "it and it will not recover. Restart the game, then the dumper.")
                return
            time.sleep(1.0)
            continue
        except Exception:
            time.sleep(1.0)
            continue
        url = snap.get("ezi_url")
        if url and url not in seen:
            seen.add(url)
            try:
                full = rpc(sc, 'ident')             # the real snapshot, once
                _d, wedged = capture(sc, full, a.out, a.name_by,
                                     read_dic=a.read_instrument_dic,
                                     use_patternjson=not a.no_patternjson)
                if wedged:
                    print("\nread path is gone — stopping the watch.\n"
                          "Restart the game, then the dumper.")
                    return
            except GameWedged as e:
                print("   !! read path is gone (%s)" % e)
                print("\nread path is gone — stopping the watch.\n"
                      "Restart the game, then the dumper.")
                return
            except Exception as e:
                print("   !! capture error: %s" % e)
        time.sleep(a.interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        _detach()
