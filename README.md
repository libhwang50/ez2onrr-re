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

into `extracted_charts/<song>/<keymode>/<difficulty>/` — for example
`extracted_charts/destr0yer/5k/hd/` — read from the running game. **Each key mode and
difficulty keeps its own capture**, so re-dumping a song at another difficulty adds a directory
rather than replacing one. `--name-by title` drops the nesting and merges every variant into one
directory (fine if you only want the song once, since one chart renders the whole song);
`--name-by id` uses the numeric music id. A song that cannot be identified falls back to
`song_<hash>`. A `403` on a `cdn_*`
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

A video of the render. `--mode default` shows the key mode + difficulty, a lane row that
lights as lanes fire, and a keysound display; `--mode keysound` shows only the keysound
display. There are no panel backgrounds — labels are outlined instead so the BGA reads through.

The keysound display lists what is *currently sounding*, each in a fixed slot with a lifetime
bar showing how far through its sample it is, so a long sample stays visible after its note
fired. The bar is a dark track under a light fill, so it reads on a bright BGA as well as a
dark one. A playing keysound keeps its slot until it ends and new ones fill the gaps, so nothing
shifts under the reader. Sample lengths are read from the keysound files, not guessed.

When a BGA is used the overlay adopts its resolution and frame rate (1280x720 at 60 fps for
Changa 2) and the BGA is passed through unscaled, so the original is preserved. That is the
default because quality comes first — `--fps`/`--size` trade it for render time, and a plain
background defaults to 1280x720 at 30 fps. Encoding defaults to `--crf 18`, near-transparent
for the BGA, and label outlines scale with the frame (1 px at 720p, `--outline` to override).

A lane lights for `--press-hold` seconds after its note fires (default 0.15) — a key press is
an event, not a duration. It is also forced dark for `--press-gap` frames before that lane's
next note (default 2), without which fast consecutive taps run together and read as a hold;
Change My World 4K SHD has 632 same-lane pairs within 0.2 s, so it shows the difference. A lane
is never dark for less than one frame, so even the tightest pair still blinks. It used to stay lit while the note's *sample* was still sounding, and
lane samples run up to 7.7 s, so a press could hold a key down for seconds; on chords several
lanes stuck at once. **Long notes are the exception:** they keep their lane lit for the whole
hold, which is `flags` ticks of the note record converted to seconds (0.2-2.6 s in practice).

`--rows auto` (the default) sizes the keysound display to the chart's peak simultaneous
keysounds **sampled at the frames actually rendered**, so nothing visible is dropped and no
column is wasted on a spike the video never shows — Rebind's true peak is 37 keysounds for
about 30 ms, which at 24 fps no frame catches, so it sizes to 26. When one column cannot fit
the chart the display spills into up to 4 columns, and key names are truncated per column so
they cannot run into a neighbour. The visualizer also warns loudly if no BGA has been
extracted, since a blank background is easy to mistake for a dark one.

The overlay is drawn as RGBA frames piped straight into ffmpeg, which composites it and muxes
the rendered audio in one pass. Anything ffmpeg can do beyond the built-in flags is reachable
with `--ffmpeg-args` (output options) and `--ffmpeg-global-args` (before the first input):

```bash
python3 visualize_song.py <song> \
    --ffmpeg-args='-tune animation -movflags +faststart -pix_fmt yuv444p'
```

The command is echoed whenever either is used, so you can see exactly what ran. Use `=` rather
than a space when the value starts with `-`, or argparse reads it as a flag.

To change the encoder use `--encoder`, which also drops the x264-only `-crf`/`-preset` for
encoders that do not take them:

```bash
python3 visualize_song.py <song> --encoder libx265                       # HEVC
python3 visualize_song.py <song> --encoder libsvtav1 --ffmpeg-args='-preset 8 -crf 30'
python3 visualize_song.py <song> --encoder h264_nvenc --ffmpeg-args='-preset p4 -cq 20 -rc vbr'
```

Putting `-c:v` in `--ffmpeg-args` instead mostly works, since it lands after the built-in flag —
but the built-in `-preset veryfast -crf 18` remain and most encoders reject `veryfast`, so it
fails for anything but another x264-family encoder. `--ffmpeg-args='-pix_fmt yuv444p'` also
switches the overlay's output format to match, so the chroma is not subsampled and then
upsampled again. Rendering runs at roughly 2x realtime at 1280x720/30fps —
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
