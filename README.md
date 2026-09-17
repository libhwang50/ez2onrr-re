# EZ2ON REBOOT: R — asset ripper & reverse-engineering toolset

Tools for decrypting and extracting assets from **EZ2ON REBOOT: R** (Unity IL2CPP):
FLAC/OGG keysounds, BGA videos, AssetBundles, and the chart payloads the game fetches
from its CDN. The full technical write-up is in **`AGENTS.md`**.

> **For archiving and personal educational use only.** All rights to the game, its
> assets, audio, video and chart files belong to Neonovice / EZ2ON REBOOT: R.

## Status

| | |
|---|---|
| ✅ AssetBundles | first 1,024 bytes XOR-encrypted (`true_key_1024.bin`); everything after is plaintext Unity data |
| ✅ Keysounds & BGA | extracted byte-exact from raw `TextAsset` / `VideoClip` objects |
| ✅ API traffic | `game1-play.ez2game.co.kr` decrypted (AES-CBC, live session key) |
| ✅ Charts & keysound index | **cracked** — `decrypt_chart.py` decrypts CDN payloads offline |

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install UnityPy frida frida-tools pefile capstone
```

The game runs under Proton/Wine with **Frida Gadget on `127.0.0.1:27042`**.
`true_key_1024.bin` must sit in the repo root; derive it once with the game running:

```bash
python3 harvest_key.py    # key = RAM_decrypted_header XOR disk_header, first 1024 B
```

## Tools

| Tool | What it does |
|---|---|
| `extract_assets.py <song> [--bga]` | keysounds (FLAC/OGG), optionally BGA `.mp4` → `extracted_assets/<song_id>/` |
| `find_bundle.py <keyword> [--decrypt\|--index]` | map bundle hashes → song codenames; build/refresh `song_index.json` |
| `decrypt_all.py [--limit N]` | bulk-decrypt `.unity3d` bundles → `EZ2ON REBOOT R/decrypted_bundles/` |
| `harvest_chart.py` | watch `InGameCore` for signed CDN URLs and fetch the chart + index |
| `dump_song.py [--out DIR] [--interval S]` | **recommended** — per-song byte-exact CDN archive + in-memory snapshot |
| `harvest_key.py` | derive `true_key_1024.bin` from live memory |
| `decrypt_chart.py <cdn_*.bin>` | **decrypt CDN chart/index payloads** → `.ez` / `.ezi` plaintext |
| `parse_chart.py <file.ez>` | **read a chart** — metadata summary, `--json`, `--notes` listing, or `--dir` over a whole archive; accepts an encrypted CDN payload directly |
| `chart_labels.py` | decrypt captured API traffic → `chart_labels.json` (song name, key mode, difficulty) |
| `render_song.py <song_dir>` | **render the song** — plays every note's keysound at its scheduled time; `--assets auto` matches the keysounds by content, `--all` walks every captured chart |
| `visualize_song.py <song_dir>` | **visualise the render** — an mp4 with the keysounds, lanes and progress overlaid on the BGA (or a plain background) |
| `song_meta.py` | look up a song's title/composer from the harvested metadata table |
| `harvest_metadata.py` | dump the game's song metadata table → `music_names.json` |

Then just **play songs**: `dump_song.py` captures each one on entry and writes

| file | contents |
|---|---|
| `ident.json` | song identity, signed URLs, field counts, per-lane note counts, and the song/mode/difficulty label |
| `cdn_ez_*.bin`, `cdn_ezi_*.bin` | the CDN payloads, byte-exact as served |
| `ez.ez`, `ezi.ezi` | the decrypted chart and keysound index |
| `mem_rjl.bin`, `mem_rjm.bin`, `mem_rjn.bin` | the buffers and transport key the game holds (the chart key is static — see below) |
| `instrumentDic.json` | the keysound index as the game parsed it |

into `extracted_charts/<song>/` — named after the song itself (`extracted_charts/destr0yer/`),
read from the running game. Use `--name-by id` for the numeric music id or `--name-by variant`
for the old `<resource>_<keymode>_<levelmode>_<gamemode>` form; when the song cannot be
identified it falls back to `song_<hash>`. A `403` on a `cdn_*`
fetch only means the signed URL expired first.

## Chart delivery

Charts are not bundled in the client — they are fetched at runtime from a CloudFront CDN
with **signed URLs that expire in ~150 s**, so a URL must be used immediately after it is
read out of game memory. The game's request headers are required (the original `403`s were
actually URL expiry, not headers):

| Header | Value |
|---|---|
| `User-Agent` | `UnityPlayer/6000.0.78f1 (UnityWebRequest/1.0, libcurl/8.10.1-DEV)` |
| `Accept` | `*/*` |
| `Accept-Encoding` | `gzip, deflate, br` |
| `X-Unity-Version` | `6000.0.78f1` |

Naming follows the EZ2AC arcade convention: **`.ez` is the note chart** (`EZFF` magic) and
**`.ezi` is the keysound index, which is plain text** (`<index> <velocity> <filename>`).
Both are served **encrypted** — see below.

### Decrypting and reading a payload

The CDN cipher is a fixed keystream XOR followed by AES-256-CBC/PKCS7, with the key and IV
baked into the binary as static fields of `InGameCore` (mask tables `svq`/`svr`; three
alternative key/IV pairs `svk`/`svl`, `svm`/`svn`, `svo`/`svp`). **Which pair a payload uses
is not recorded anywhere** — exactly one of them gives valid PKCS7 padding, so the
decryptor tries all three and keeps the one that yields a real chart or index. It is *not*
per-song: an earlier per-song-key theory came from `bundleCryptKey`, which is a session
record and not the chart key. Full derivation in `AGENTS.md` §3.3.

```bash
# decrypt a captured payload (dump_song.py already writes these decrypted)
python3 decrypt_chart.py --out extracted_charts/_decrypted extracted_charts/_live/*.ez

# read it — header summary, full JSON, or a per-note listing
python3 parse_chart.py extracted_charts/_decrypted/cur_conflict_ez_url.ez
python3 parse_chart.py --json chart.json extracted_charts/_decrypted/cur_conflict_ez_url.ez
python3 parse_chart.py --notes --ezi extracted_charts/_decrypted/cur_conflict_ezi_url.ezi \
    extracted_charts/_decrypted/cur_conflict_ez_url.ez

# every chart under a tree, decrypting captures as needed
python3 parse_chart.py --dir extracted_charts
python3 parse_chart.py --dir extracted_charts --json archive.json

# which keysound is the full song? (track 22's note — the filename varies)
python3 parse_chart.py --backing --ezi song/ezi.ezi song/ez.ez
```

### Visualising a render

```bash
python3 visualize_song.py extracted_charts/changa2            # -> visualizations/changa2.mp4
python3 visualize_song.py <song> --no-bga --size 1920x1080 --fps 60
```

A video of the render: a top bar with the title/variant/composer and a progress bar, a lane
row that lights as lanes fire, and a ticker of the most recent keysounds with lane, index and
filename. It uses the song's BGA when one has been extracted, otherwise a plain background.

The overlay is drawn as RGBA frames piped straight into ffmpeg, which composites it and muxes
the rendered audio in one pass. Rendering runs at roughly 2x realtime at 1280x720/30fps —
`--fps`, `--size` and `--until` trade that off.

`parse_chart.py` also accepts an encrypted payload straight from the CDN, so
`python3 parse_chart.py extracted_charts/_live/cur_conflict_ez_url.ez` works too.

> **Where is the full song?** It does not exist as a file. **The song is a render of the
> chart**: every type-1 note, on every track, triggers its keysound at its scheduled time.
> The keysound triggered once by **track 22** (`00-MR.flac`, `MR.flac`, or for
> `ae_illusion` `mrt22Fix.flac`) is **not** the full song — it holds only the instruments
> too long or too incidental to sample as keysounds (for Rebind, just ambience).
> `parse_chart.py --backing` finds that layer, and `render_song.py` builds the song. See
> `AGENTS.md` §3.5.
>
> **One chart per song is enough.** Difficulty and key mode do not change the song — they
> move notes between the player's lanes and the auto-played tracks. PUPA 5K HD and 5K NM
> have identical note-event sets and render to byte-identical audio, and the `.ezi`
> keysound index is byte-identical for every variant of a song.
>
> **The Lounge harvests charts without gameplay.** Watching a BGA in the in-game Lounge
> goes through the same download flow and serves the song's **4K EZ** chart — so browse the
> Lounge and `dump_song.py` collects each song's chart, which is all the renderer needs.

### Rendering a song

```bash
python3 render_song.py extracted_charts/<song> --assets auto -o song.flac
python3 render_song.py --all -o rendered_songs/        # every captured chart
```

**Verified by ear against in-game gameplay — reported as an exact match.** Long notes need
no special handling: their keysound plays once, exactly like a normal note, and is not
sustained.

`--assets auto` resolves which `extracted_assets/<song_id>` belongs to a chart by
matching the `.ezi` keysound filenames against the files on disk (exact, 100%, for every
song here). Rendering is fast — the 5 captured songs render in 11 s.

## ⚠️ Two rules for the Frida tooling

1. **Never `Interceptor.attach`** — every hook attempt has crashed the game, including on
   cold, once-per-launch functions. **Never `MemoryAccessMonitor`** on a shared or hot page
   (above all `da`'s statics) — it crashes too.
2. **Rebuild symbol maps every session** — `GameAssembly.dll`'s base moves between
   launches, and AOT method bodies are decrypted lazily, so a code scan misses any method
   that has not yet run.

The safe pattern is read-only memory reads, managed calls on the game's main thread
(`onMain()`), and host-side polling at ≤4 Hz. Details in **`tools/README.md`**.

## Repository layout

```
AGENTS.md            full technical report
README.md
true_key_1024.bin    master bundle XOR key
song_index.json      bundle-hash → song index
extract_assets.py  find_bundle.py  decrypt_all.py
harvest_key.py  harvest_chart.py  dump_song.py  decrypt_chart.py  parse_chart.py  run_dumper.sh
render_song.py
tools/               investigation tooling — see tools/README.md
  il2cpp/  probes/  mitm/  crypto/  legacy/
data/  logs/  mitm_live/  mitm_parsed/  il2cpp_code/    ignored capture artefacts
extracted_assets/  extracted_charts/                     outputs
```

After editing a Frida driver, regenerate the runnable `*_run.js` files:

```bash
bash tools/il2cpp/build_run.sh
```

## Disclosure

Written with AI assistance (Qwen3.6 35B-A3B, Gemini 3.6 Flash); all output reviewed by a
human. Use for archiving purposes only.
