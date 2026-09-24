# EZ2ON REBOOT: R — asset ripper & reverse-engineering toolset

Tools for decrypting and extracting assets from **EZ2ON REBOOT: R** (Unity IL2CPP):
keysounds, BGA videos, AssetBundles, and the chart payloads the game fetches
from its CDN. The technical write-up is in **`docs/`** (index), or as a brief in **`AGENTS.md`**.

> **For archiving and personal educational use only.** All rights to the game, its
> assets, audio, video and chart files belong to Neonovice / EZ2ON REBOOT: R.

## Status

| What is done | Details |
|---|---|
| ✅ AssetBundles | first 1,024 bytes XOR-encrypted (`true_key_1024.bin`); everything after is plaintext Unity data |
| ✅ Keysounds & BGA | extracted byte-exact from raw `TextAsset` / `VideoClip` objects |
| ✅ API traffic | `game1-play.ez2game.co.kr` decrypted (AES-CBC, live session key) |
| ✅ Charts & keysound index | **cracked** — `ripper/decrypt_chart.py` decrypts CDN payloads offline |
| ✅ **Private server (standalone, multi-user)** | login → music list → profile → chart download → leaderboard, served locally or from a homeserver (`server/`, Docker included). Per-user progression + server-issued accounts; the client runs Frida-free via a pubkey-swap `version.dll` |
| ✅ **Fully offline songs (confirmed in game)** | no official server contact at all: the CloudFront URL signature is never verified, and `bundleCryptKey` is minted server-side (it is AES-CBC of a client-side *constant* under the live session key — §3.2). The only input from the running game is its session key, which it never sends |

## Private server

`server/` is a **standalone** server — no mitmproxy needed on the host. It serves
login, the music list, profiles, chart downloads and leaderboards, with per-user
progression and server-issued accounts. It runs either as a local mitmproxy addon
the game already points at, or as a plain HTTP(S)/ASGI service (Docker Compose
included) for a public homeserver.

```bash
# local, single machine (the game's Wine proxy already points at mitmproxy)
python server/_rsa.py init            # once — the client version.dll embeds this key
mitmdump -s server/_pserver.py

# standalone (public / homeserver)
python server/app.py --host 0.0.0.0 --port 8081      # or: docker compose up -d
docker compose --profile caddy up -d                 # optional TLS front end
```

**No Frida by default.** The drop-in `client/patcher/version.dll` rewrites the
build's baked-in RSA public key to ours, so `c2s_login` hands the server both the
session key and the identity (`server/_rsa.py`). The memory harvester remains a
fallback for an unpatched client. For a public server the client runs a thin relay
(`server/_relay.py`) to the remote `server/app.py`, and access is gated by accounts
/ bearer tokens with a configurable guest tier (`server/_auth.py`,
`server/_accounts.py`).

Songs load **fully offline** with no setup step: the server mints its own CDN URLs
and `bundleCryptKey`, and forwards nothing. Chart matching is exact (the capture for
the requested key mode and difficulty). Coverage is per song; `server/re/_coverage.py`
reports it and `server/_build_data.py` regenerates the data from your own captures.

Full guides: **`server/README.md`** (running, Docker, identity, the offline recipe)
and **`client/README.md`** (the patcher, and Goldberg for players with no Steam
account).

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# or with uv (what this repo's .venv was built with):
uv venv .venv && uv pip install --python .venv/bin/python -r requirements.txt
```

`requirements.txt` lists everything the tools, the private server and the investigation
scripts need, grouped by which part of the toolset uses it. The only hard requirements for
the offline ripper are **UnityPy** (bundles) and **pycryptodome** (the ciphers); `mutagen`
is optional (FLAC tags) and `frida` is only needed for the live-game reads.

The game runs under Proton/Wine. **Frida is only needed for the *live-game read*
tools** (`ripper/dump_song.py`, `ripper/harvest_key.py`, `ripper/harvest_metadata.py` and the
`tools/il2cpp` drivers), which attach to a Frida Gadget on `127.0.0.1:27042`. The
private server no longer needs it: the client-side `version.dll` patcher
(`client/patcher/`) handles the session-key hand-off, and the memory harvester is
a fallback. `true_key_1024.bin` must sit in the repo root; derive it once with the
game running and a song loaded:

```bash
python3 ripper/harvest_key.py    # key = RAM_decrypted_header XOR disk_header, first 1024 B
```

## Tools

| Tool | What it does |
|---|---|
| `ripper/extract_assets.py <song> [--bga]` | keysounds (FLAC/OGG), optionally BGA `.mp4` → `extracted_assets/<song_id>/` |
| `ripper/find_bundle.py <keyword> [--decrypt\|--index]` | map bundle hashes → song codenames; build/refresh `song_index.json` |
| `ripper/find_bundle.py --decrypt-all [--limit N]` | bulk-decrypt `.unity3d` bundles → `EZ2ON REBOOT R/decrypted_bundles/` |
| `ripper/dump_song.py [--out DIR] [--interval S]` | **recommended** — per-song byte-exact CDN archive + in-memory snapshot |
| `ripper/harvest_key.py [--out FILE]` | **derive `true_key_1024.bin`** from live memory, validated against the bundles on disk |
| `ripper/decrypt_chart.py <cdn_*.bin> [--keypair …]` | **decrypt CDN chart/index payloads** → `.ez` / `.ezi` plaintext |
| `ripper/decrypt_chart.py --archive [DIR …]` | **complete chart dumps** — decrypt every raw CDN capture in a tree (default `extracted_charts/`), writing `ez.ez` / `ezi.ezi` / `instrumentDic.json`; `--check` audits without writing |
| `ripper/parse_chart.py <file.ez>` | **read a chart** — metadata summary, `--json`, `--notes` listing, or `--dir` over a whole archive; accepts an encrypted CDN payload directly |
| `ripper/chart_labels.py` | decrypt captured API traffic → `chart_labels.json` (song name, key mode, difficulty) |
| `ripper/check_charts.py` | **audit the captures** — flags a chart filed under the wrong key mode or difficulty, a missing artifact, or a record that disagrees with the chart on disk; exits non-zero |
| `ripper/render_song.py <song_dir>` | **render the song** — plays every note's keysound at its scheduled time; `--assets auto` matches the keysounds by content, `--all` walks every captured chart |
| `ripper/visualize_song.py <song_dir>` | **visualise the render** — an mp4 with the keysounds, lanes and progress overlaid on the BGA (or a plain background). Pass a song directory or `--all` to render every variant, `--skip-existing` to leave finished ones |
| `ripper/song_meta.py` | look up a song's title/composer from the harvested metadata table |
| `ripper/harvest_metadata.py` | dump the game's song metadata table → `music_names.json` |

`ripper/ez2lib.py` is the shared internal helper (key loading, bundle-header decryption, capture
labels) — it is imported by the tools above, not run directly.

Then just **play songs**: `ripper/dump_song.py` captures each one on entry and writes

| file | contents |
|---|---|
| `ident.json` | song identity, signed URLs, field counts, per-lane note counts, and the song/mode/difficulty label |
| `cdn_ez_*.bin`, `cdn_ezi_*.bin` | the CDN payloads, byte-exact as served |
| `ez.ez`, `ezi.ezi` | the decrypted chart and keysound index |
| `mem_rjl.bin`, `mem_rjm.bin`, `mem_rjn.bin` | the buffers and transport key the game holds (the chart key is static — see below) |
| `instrumentDic.json` | the keysound index as the game parsed it — **only with `--read-instrument-dic`** (see the note below) |

into `extracted_charts/<song>/<keymode>/<difficulty>/` — for example
`extracted_charts/destr0yer/5k/hd/` — read from the running game. **Each key mode and
difficulty keeps its own capture**, so re-dumping a song at another difficulty adds a directory
rather than replacing one. `--name-by title` drops the nesting and merges every variant into one
directory (fine if you only want the song once, since one chart renders the whole song);
`--name-by id` uses the numeric music id. A song that cannot be identified falls back to
`song_<hash>`. A `403` on a `cdn_*`
fetch only means the signed URL expired first.

The capture directory is chosen by the **chart's own identity**, not just the runtime label:
the game updates `ez_url`/`ezi_url` in stages, so a snapshot can catch the old label with the
new chart. If they disagree and a capture already exists, the snapshot goes to
`<name>_mismatch/` rather than overwriting the real one.

`instrumentDic.json` is **off by default** (`--read-instrument-dic` to enable). Walking the
game's dictionary is ~4 managed invocations per entry — ~8,000 for Ultimatum's 2,014 — and
the Frida bridge holds the enumerator and its boxed keys as raw pointers the IL2CPP GC is
never told about, so a GC mid-loop can free them. It is only a cross-check anyway; `ezi.ezi`
carries the same index → filename mapping. (This was added while chasing the freezes on the
theory that it caused them; it did not — the hang was caught in a read that invokes nothing —
but the unpacked-pointer risk is real, so it stays opt-in.)

The captures are audited with `ripper/check_charts.py`, which flags a chart filed under the wrong
key mode or difficulty (the mislabelling bug filed a 4K chart under `5k/shd`), a missing
artifact, or a record that disagrees with the chart on disk.

If the read path dies — the game's main thread is wedged (spinning), has exited, or the Frida
script is unloaded — the watch says so and stops rather than hanging or polling forever. Each
call is bounded by a timeout, so a livelocked read reports instead of blocking on a futex. A
capture interrupted that way still writes `ident.json`, with an `incomplete` list of what it
could not read.

Reads run on Frida's own thread. `--on-main` puts them back on the game's main thread via
`Process.runOnThread`, which is only needed for a call into the OS crypto provider — that
hijack has livelocked the main thread under Proton (100% CPU, gadget wedged, reads never
return), so it is off by default.

**Kill a crashed game before relaunching.** A dead game's husk keeps the gadget's port
(`127.0.0.1:27042`) bound, so a relaunched game's gadget cannot listen and `ripper/dump_song.py`
attaches to the corpse. It checks the first read and says so, but
`pgrep -af EZ2ON.exe` and kill any leftover first.

`--no-patternjson` skips the `rw-` range sweep that reads the in-play request JSON out of
memory and takes the label from `chart_labels.json` instead. It is the switch for testing
whether that sweep is what a crash lands on.

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
record and not the chart key. Full derivation in §3.3.

```bash
# decrypt a captured payload (ripper/dump_song.py already writes these decrypted)
python3 ripper/decrypt_chart.py --out extracted_charts/_decrypted extracted_charts/_live/*.ez

# read it — header summary, full JSON, or a per-note listing
python3 ripper/parse_chart.py extracted_charts/_decrypted/cur_conflict_ez_url.ez
python3 ripper/parse_chart.py --json chart.json extracted_charts/_decrypted/cur_conflict_ez_url.ez
python3 ripper/parse_chart.py --notes --ezi extracted_charts/_decrypted/cur_conflict_ezi_url.ezi \
    extracted_charts/_decrypted/cur_conflict_ez_url.ez

# every chart under a tree, decrypting captures as needed
python3 ripper/parse_chart.py --dir extracted_charts
python3 ripper/parse_chart.py --dir extracted_charts --json archive.json

# which keysound is the full song? (track 22's note — the filename varies)
python3 ripper/parse_chart.py --backing --ezi song/ezi.ezi song/ez.ez
```

### Visualising a render

```bash
python3 ripper/visualize_song.py extracted_charts/changa2            # -> visualizations/changa2.mp4
python3 ripper/visualize_song.py <song> --no-bga --size 1920x1080 --fps 60
python3 ripper/visualize_song.py extracted_charts/ultimatum         # bulk: every variant under it
python3 ripper/visualize_song.py --all --skip-existing              # every chart, skipping ones done
```

A video of the render. `--mode default` shows the key mode + difficulty, a lane row that
lights as lanes fire, and a keysound display; `--mode keysound` shows only the keysound
display. There are no panel backgrounds — labels are outlined instead so the BGA reads through.

Keysound rows are coloured by who plays them: the chart's own lanes are bright white for a
tap and bright yellow for a long note, while auto-played notes (the track-22 `MR` layer and
the instrument layers) are dimmed grey / dim amber. `--no-auto-dim` turns that off and
colours every row alike.

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

A lane lights for `--press-hold` seconds after its note fires (default 0.05) — a key press is
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
python3 ripper/visualize_song.py <song> \
    --ffmpeg-args='-tune animation -movflags +faststart -pix_fmt yuv444p'
```

The command is echoed whenever either is used, so you can see exactly what ran. Use `=` rather
than a space when the value starts with `-`, or argparse reads it as a flag.

To change the encoder use `--encoder`, which also drops the x264-only `-crf`/`-preset` for
encoders that do not take them:

```bash
python3 ripper/visualize_song.py <song> --encoder libx265                       # HEVC
python3 ripper/visualize_song.py <song> --encoder libsvtav1 --ffmpeg-args='-preset 8 -crf 30'
python3 ripper/visualize_song.py <song> --encoder h264_nvenc --ffmpeg-args='-preset p4 -cq 20 -rc vbr'
```

Putting `-c:v` in `--ffmpeg-args` instead mostly works, since it lands after the built-in flag —
but the built-in `-preset veryfast -crf 18` remain and most encoders reject `veryfast`, so it
fails for anything but another x264-family encoder. `--ffmpeg-args='-pix_fmt yuv444p'` also
switches the overlay's output format to match, so the chroma is not subsampled and then
upsampled again. Rendering runs at roughly 2x realtime at 1280x720/30fps —
`--fps`, `--size` and `--until` trade that off.

`ripper/parse_chart.py` also accepts an encrypted payload straight from the CDN, so
`python3 ripper/parse_chart.py extracted_charts/_live/cur_conflict_ez_url.ez` works too.

> **Where is the full song?** It does not exist as a file. **The song is a render of the
> chart**: every type-1 note, on every track, triggers its keysound at its scheduled time.
> The keysound triggered once by **track 22** (`00-MR.flac`, `MR.flac`, or for
> `ae_illusion` `mrt22Fix.flac`) is **not** the full song — it holds only the instruments
> too long or too incidental to sample as keysounds (for Rebind, just ambience).
> `ripper/parse_chart.py --backing` finds that layer, and `ripper/render_song.py` builds the song. See
> §3.5.
>
> **One chart per song is enough.** Difficulty and key mode do not change the song — they
> move notes between the player's lanes and the auto-played tracks. PUPA 5K HD and 5K NM
> have identical note-event sets and render to byte-identical audio, and the `.ezi`
> keysound index is byte-identical for every variant of a song.
>
> **The Lounge harvests charts without gameplay.** Watching a BGA in the in-game Lounge
> goes through the same download flow and serves the song's **4K EZ** chart — so browse the
> Lounge and `ripper/dump_song.py` collects each song's chart, which is all the renderer needs.

### Rendering a song

```bash
python3 ripper/render_song.py extracted_charts/<song> --assets auto -o song.flac
python3 ripper/render_song.py --all -o rendered_songs/        # every captured chart
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
AGENTS.md / docs/    project brief + full technical report
README.md
requirements.txt     Python deps for the ripper + live tools (see Setup)
ruff.toml            lint gate
true_key_1024.bin    master bundle XOR key (derive with ripper/harvest_key.py)
song_index.json      bundle-hash → song index
ripper/ez2lib.py            shared helpers — imported by the tools, not run directly
Dockerfile  docker-compose.yml  deploy/Caddyfile   standalone server container

ripper/extract_assets.py  ripper/find_bundle.py                  bundles → assets / index
ripper/dump_song.py  ripper/harvest_key.py                       live-game reads over the Frida Gadget
ripper/decrypt_chart.py  ripper/parse_chart.py  ripper/check_charts.py  chart ciphers, readers and audits
ripper/chart_labels.py  ripper/harvest_metadata.py  ripper/song_meta.py naming and metadata
ripper/render_song.py  ripper/visualize_song.py                  render and visualise a song
server/              private server + capture automation — see server/README.md
  app.py _core.py _flowshim.py                     standalone HTTP(S)/ASGI server
  _pserver.py _relay.py _fake_client.py            game logic, client relay, test client
  _auth.py _accounts.py _store.py _sessions.py     identity, accounts, progression
  _rsa.py _build_data.py _harvest_mem.py           key hand-off, data build, fallback
  _screen.py _sweep.py _coverage.py                guided chart capture
client/              Frida-free version.dll patcher — see client/README.md
tools/               reverse-engineering toolbox — see tools/README.md
  il2cpp/  probes/  mitm/  crypto/
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
