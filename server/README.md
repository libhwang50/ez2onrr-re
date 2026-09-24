# EZ2ON REBOOT:R — basic private server

A first working private-server implementation for the Standard/Basic online
flow. It stubs the game's three HTTPS hosts entirely server-side and keeps the
raw-TCP channels (battle/control, raw IPs) pointed at the real servers.

**Chart loads work fully offline by default** (no official login, no
CloudFront, no borrowed token): the URL signature is never verified and
`bundleCryptKey` is minted here — it is AES-256-CBC/PKCS7 of a **client-side
constant** under the client's live session key. No `_exp.py` setup step is
needed; the offline recipe *is* the default. See "Fully offline chart loads"
below.


Everything cryptographic is already solved (see AGENTS.md §3.1/§3.3); this is
"just" the serving layer.

## How it works

The game's Wine prefix already routes WinHTTP through mitmproxy
(`ProxyEnable=1` → `127.0.0.1:8080`) and trusts the mitmproxy CA. So the
private server is a **mitmproxy addon** that intercepts the three game hosts
and never contacts the upstream:

| host | what we serve |
|---|---|
| `game1-play.ez2game.co.kr` | the API: `c2s_login`, `c2s_get_gameinfo`, `c2s_get_myinfo`, `c2s_get_pattern_file`, `c2s_set_game_clear`, `c2s_get_userinfo` — AES-256-CBC/PKCS7 with the client's own session key |
| `game1-rank.ez2game.co.kr` | `get_battle_server_ip` (real battle server), leaderboard CSVs, and empty 200s for `rating` / `totalranking` / `plf…` (score upload accepted and logged) |
| `game1-cdn.ez2game.co.kr` | chart/`.ezi` ciphertext blobs, served from the local capture archive |

Wire format (verified byte-for-byte against captures):

* API **request**  = form fields; the `data` field holds
  urlenc(b64( magic`d3ad76d3adb8` ‖ AES-CBC-PKCS7(json) )). `c2s_login`
  additionally carries `ticket=<Steam ticket>` and `identity=<SteamID>`.
* API **response** = b64( AES-CBC-PKCS7(json) )
* key/IV = the ASCII bytes of `zf.aes_key` / `zf.aes_iv` — generated
  **client-side** per session (`zf.gnf`: `RNGCryptoServiceProvider` →
  `BitConverter.ToString` → strip `-`). They never appear on the HTTPS wire in the
  clear, but the login block is **RSA under the client's baked-in `zf.publicKey`** and
  its plaintext is the client's login JSON
  `{"steamid","appid","version","key","iv"}` — so a client carrying the drop-in
  `version.dll` (`client/patcher/`) hands the server the key, the IV **and the
  SteamID** with no harvester. See "The Frida-free login hand-off" below. The memory
  scanner `_harvest_mem.py` remains as a fallback for an unpatched client, and the
  Frida bridge `_harvest_session.py` after that.

**No upstream leakage.** An unhandled exception inside a mitmproxy addon hook
does not abort the request — mitmproxy forwards it to the real upstream. The
first test run therefore mixed real and private responses invisibly. The addon
now catches every failure on a game host and serves an explicit error instead;
a game-host request must never leak upstream. (Level/rating seen in-game during
a mixed session came from the real servers — with a clean run they come from
`data/profile.json`.)

Validated in-game (one session): login → music list → profile → Finite 5K HD
chart + `.ezi` served from cache → played → score upload logged. The leaderboard
profile fetch (`c2s_get_userinfo`) serves `{memberinfo:[{STEAM_ID,LEVEL,RATING}],
result}` — the DTO field set was recovered from `global-metadata.dat` when the
account was lost and the official capture could no longer be decrypted (the
session key had rotated away); see AGENTS.md §3.2.

## Files

| file | purpose |
|---|---|
| `_pserver.py` | the mitmproxy addon (the server itself); logs to `pserver.log`; never forwards game-host traffic upstream |
| `_sessions.py` | per-user API session registry: `steamid -> {key, iv}`, with an address cache and trial decryption for the SteamID-less requests |
| `_store.py` | per-user progression store (SQLite, `data/store.db`): `memberinfo` + the 16-wide `clearlist` arrays, normalised to one row per cleared variant; seeds the owner from the captured `myinfo.json` |
| `_rsa.py` | server keypair + **strict** RSA decode of the login block (`init`/`show`/`decrypt`/`selftest`). The old `cryptography` PKCS#1 v1.5 call was not a validity oracle (82% of random blocks "decrypted"); this is |
| `_login_probe.py` | standalone probe: captures `c2s_login`, strict-decodes `data`, reports the payload shape. The experiment that pinned the login JSON |
| `_harvest_mem.py` | **fallback** session key: scans the game's memory for the `"key":"…","iv":"…"` JSON the client builds at login → `session_key.json`. Handles relaunches/rotations; keeps the last key (the JSON is transient). Linux needs `ptrace_scope=0`/sudo, Windows is same-user |
| `_harvest_session.py` | Frida bridge (fallback): polls `zf.aes_key`/`aes_iv` at 1 Hz → `session_key.json`; **auto-re-attaches when the game restarts** |
| `_build_data.py` | (re)builds `data/` from the captured artefacts in the repo |
| `data/login.json` | `c2s_login` response template (real, captured) |
| `data/myinfo.json` | `c2s_get_myinfo` template — `clearlist`, `memberinfo`, … |
| `data/gameinfo.json` | `c2s_get_gameinfo` template — the 1,201-entry music list |
| `data/profile.json` | your member-field overrides (`LEVEL`, `EXP`, …), deep-merged into the `c2s_get_myinfo` template. The real `memberinfo` DTO has **no nickname field** — the name shown in game and sent in `plf…` is the Steam persona name from Steamworks. The in-game rating shown per key mode is **computed client-side** from your play data — `RATING` here only sets the myinfo field |
| `data/charts.json` | (song, keymode, levelmode) → CDN paths, 47 variants / 15 songs |
| `data/cdn_paths.json` | CDN path → local ciphertext file (126 paths) |
| `data/rank_sample.csv` | fallback leaderboard body when no exact capture matches |
| `data/rank_csv/` | real leaderboard CSVs per query (Top100 / MyRange of captured songs), served exactly |
| `data/userinfo_entry.json` | optional override of one `c2s_get_userinfo` entry; the shape is **solved** — `{STEAM_ID, LEVEL, RATING}` (AGENTS.md §3.2), there is no nickname field |
| `data/bundleCryptKey.txt` | value served as `bundleCryptKey` when no knob overrides it |
| `data/set_game_clear.json` | optional override for `c2s_set_game_clear` (real shape `{level, exp, nextExp, result}`; the built-in fallback uses `profile.json`) |
| `data/mutate_urls.txt` / `data/mutate_bck.txt` | the experiment knobs written by `_exp.py` (read per request) |
| `data/passthrough_endpoints.txt` | endpoints forwarded upstream (hybrid mode), read per request |
| `data/last_upstream_*.json` / `…​.full.json` | the last decrypted upstream response (shortened / with real URLs+key) |
| `_exp.py` | control the experiment knobs from the shell (`hybrid`, `urls`, `bck`, `off`, `reset`) |
| `_mem.py` | drive the harvester's command channel: `findhex`, `findlea`, `findlit`, `findthunk`, `readbytes`, `bck` |
| `_stub443.py` | loop-proof TLS stub for the game's un-proxied 443 channel (mitmproxy-CA-signed cert) |
| `_stub9902.py` | capturing TCP relay for the raw packet/battle channel; address comes from `data/battle_server.txt`. This is where the client's `sendaes,` AES-key hand-off is expected to land (AGENTS.md §3.1) |
| `_rawchannel.sh` | `on`/`test`/`status`/`off` — redirects the un-proxied channel into `_stub443.py` |

All of `data/` is generated locally and git-ignored (it contains your profile, play
history, the music DB and captured key material). Rebuilding needs the session key of
the capture that produced the API templates — session keys are never committed, so
export them first:

```bash
export EZ2_API_SESSION_KEY=<32-char ASCII zf.aes_key of that session>
export EZ2_API_SESSION_IV=<16-char ASCII zf.aes_iv of that session>
.venv/bin/python server/_build_data.py
```

## Running

**Default (Frida-free, patched client) — no harvester, no memory scan.**

```bash
bash client/patcher/install.sh patcher     # install the DLL into the game dir (once)
# Proton only, in the Steam launch options:  WINEDLLOVERRIDES=version=n,b
mitmdump -s server/_pserver.py             # the server
```

Then start the game normally. `server/pserver.log` should show
`session key <- RSA login: … (steamid …)` — the login block is decrypted server-side
and that is the entire hand-off.

**Fallback (unpatched client) — memory harvester.**

```bash
# Linux: one-time `sudo sysctl -w kernel.yama.ptrace_scope=0` (ptrace access)
# Windows: same-user, nothing to enable
/usr/bin/python server/_harvest_mem.py
```

**Ordering no longer matters** in either mode: the login handler waits up to 15–20 s
for a key, and the RSA path adopts a fresh block on every `c2s_login` (so relaunches
and the within-launch key rotation are tracked automatically).
(`_harvest_session.py`, the Frida bridge, still works after that.) Without any key
the login can only fail — the client pops "Object reference not set…" and OK quits
the game, because a response cannot be encrypted without the key.

⚠ The **Frida** bridge never attaches while the game is starting up: an attach
during the early startup window kills the process instantly (no crash handler). It
watches the Gadget's TCP port and attaches only after it has been listening
continuously for `EZ2_HARVEST_GRACE` seconds (default 15; raise it if you ever
see a launch die silently, lower it if the private-server login ever times out
on a cold launch).

Notes:

* The Wine proxy must point at the mitmdump instance (`ProxyEnable=1`,
  `ProxyServer=127.0.0.1:8080`) — the same setting used for every capture so far.
* Pattern lookup is **exact-match only** (song + keymode + levelmode): serving a
  different difficulty's chart would load wrong notes. Uncaptured songs fail
  with `result:0`; the client retries 5× then boots to the main screen.
* Only songs with a captured chart are playable (see `charts.json`); add more by
  running `dump_song.py`/captures and re-running `_build_data.py`.
* Score uploads (`plf…`) are logged but stored nowhere yet; leaderboards serve
  real captured CSVs when available (`data/rank_csv/`, Top100 + MyRange for
  Finite) and fall back to a static sample.

## Fully offline chart loads — WORKING, and what's still open

The client does **not** verify the CloudFront URL signature, does not care about
`Expires`, and accepts a response we build entirely ourselves. It checks exactly
one thing: the 48-byte `bundleCryptKey`. And the failure it raises otherwise is
not an integrity complaint at all — the code is literally:

```
8CN26Song Load timeout1YDMD : m:K14JVmLV Error : id:{0} m:{1}
An unrecoverable error has occurred.
```

i.e. **8CN26 = "Song Load timeout"** (that string pair sits in the game's literal
pool; see `AGENTS.md` §3.7).

### What the bCK actually is (solved)

`bundleCryptKey` is not a key. It is

```
base64( AES-256-CBC/PKCS7( 32-byte constant ) )
```

under the client's **own live session key and IV** (ASCII) — the very cipher the
API bodies use. The payload is a **build-time constant of the client**
(`d3163d64…`, written to `server/data/bck_payload.hex`), so the server can mint a
byte-identical token with no official server involved. It is a knowledge proof:
the server shows it knows the client's session key by encrypting a fixed
plaintext, and the client compares the result with its own copy of the constant.

That is why the two failure modes look so different:

| what the client got | outcome |
|---|---|
| a token that **cannot decrypt** (random bytes, or another session's token) | **8CN26 "Song Load timeout"** — a *wait*, so it reads like corruption |
| a token that decrypts but carries the **wrong payload** | **tamper kill** — "An unrecoverable error has occured. The program will now be terminated." |

With no session key at all the server cannot mint anything, so `session_key.json`
(care of the harvester) stays the single input from the running game. Note the key
**rotates within a launch**, so it must be re-read per request — `_pserver.py`
does that already.

### The knobs and what they proved

**Offline is the default now.** With no knob files the addon forwards nothing
and mints its own CDN `Expires` and `bundleCryptKey`. The knobs below *override*
that default (and `off`/`none` turns a piece of it off for an experiment), so
the old `hybrid off` + `urls now` + `bck mint` recipe is what happens on a fresh
install with no setup. Chart serving stays **exact** by default; `chart any` is
a deliberate override because a chart's note assignment is per
keymode/difficulty.

```bash
python server/_exp.py                 # show state (and the effective defaults)
python server/_exp.py chart any       # serve any captured variant of the song (opt-in; wrong lanes)
python server/_exp.py chart exact     # only the exact keymode/difficulty (the default)
python server/_exp.py hybrid off      # no passthrough (the default)
python server/_exp.py urls now        # mint our own Expires = now+150 (the default)
python server/_exp.py bck mint        # mint the token (the default)
python server/_exp.py bck mint:zero   # ... with a zero payload (diagnostic)
python server/_exp.py bck harvested   # or reuse the token from a captured response
python server/_exp.py urls off        # raw replay, no URL rewrite
python server/_exp.py bck off         # raw replay, no token mint
python server/_exp.py off             # clear the url/bck/chart mutations -> offline defaults
python server/_exp.py reset           # clear everything -> offline defaults
```

| run | knob | result | conclusion |
|---|---|---|---|
| A | none (hybrid) | loads | baseline |
| B | `bck garbage` | 8CN26 | the token must decrypt (padding) |
| C | `urls skew` (`Expires` +1 s → invalid signature) | **loads** | the URL signature is **never** verified |
| D | `bck mint:random` | **tamper kill** | a decryptable token with the wrong payload is fatal |
| E | `bck harvested` (fresh, same session) | loads | the control |
| F | `bck mint` (client constant, live key) | **byte-identical to E's token** | the server can mint it itself |

### The offline recipe

No official contact at all, and **no setup step** — this is the default. The
protocol-level token is minted from the client's hardcoded build constant and the
live session key:

```bash
/usr/bin/python server/_harvest_mem.py        # terminal 1: keeps session_key.json live
mitmdump -s server/_pserver.py                # terminal 2: the server
```

The three `_exp.py` commands that used to be required are now the built-in
defaults (`urls now`, `bck mint`, no passthrough). Running them is
harmless and remains useful to re-assert the state after experiments:

```bash
python server/_exp.py hybrid off              # no passthrough
python server/_exp.py urls now                # our own CDN URLs
python server/_exp.py bck mint                # mint the token from the live key
```

Then every captured song entry loads with our login, our music list, our profile,
our minted URL, our cached CDN files and a token we produced — **confirmed in game**
(Finite 5K HD loads and plays with `endpoints = ''`). Verified three ways: by
decrypting the response the client accepted, by minting a token byte-identical to
the one the official server had served moments earlier, and by finding the client's
own single `byte[32]` copy of the constant in memory next to its live session key.

### Growing the chart archive

Coverage is **per song, not per variant**: the client never picks the CDN path
(it downloads whatever URL the server returns), so one capture of a song serves
every keymode/difficulty of it, and the `.ezi` is already identical across a
song's variants. `_exp.py chart any` does that mapping; `chart exact` is for
capturing, because a miss must reach upstream for the body to be recorded.

```bash
python server/_coverage.py            # 16/601 songs (2.7%), and which are missing
python server/_coverage.py --queue    # write the capture queue (music-list order)
python server/_coverage.py --log      # what the game asked for vs what we could serve
```

The loop that adds songs, end to end:

1. **`_exp.py harvest`** — forwards `login,pattern,cdn` upstream. The API
   passthrough is what mints a real session and real signed URLs; **`cdn` is what
   lets a chart we do not hold yet come from the official CDN** (without it a
   missing chart is a local 404 and nothing can ever be captured).
2. Walk the song list (the game, or `server/_sweep.py`) so it asks for each song.
3. The addon files every forwarded CDN body straight into
   **`extracted_charts/<song>/<km>/<diff>/`** — `cdn_ez_cap.bin`, `cdn_ezi_cap.bin`
   and an `ident.json` with the URLs and the label — i.e. the same layout
   `dump_song.py` writes, so the archive stays the single source of truth and no
   side pipeline exists. It also decrypts them on the spot into `ez.ez` /
   `ezi.ezi` (naming the key pair in `ident.json`) and derives
   `instrumentDic.json` from the `.ezi`, so a capture ends up a complete dump.
   `capturedBy: "sweep"` marks the ones that came this way, and
   **`python decrypt_chart.py --archive`** fills in any plaintext that is missing
   (the tool walks the archive and is safe to re-run; `--check` reports only).
4. **`python server/_build_data.py`** folds the archive into
   `server/data/charts.json` + `cdn_paths.json`, then `_coverage.py` shows the
   result.

The addon only lets a CDN request out when `cdn` is in the passthrough list — in
`offline` mode nothing leaves the machine, and an uncached chart is a plain 404.

`server/_sweep.py` automates that walk. The server log is its primary sensor — every
request names the song, keymode, levelmode and gamemode — and a screen-state classifier
(`server/_screen.py`, below) is the *safety* sensor. It refuses to send keys unless the
focused window really is the game (`niri msg focused-window`), so it cannot type into
your terminal.

```bash
python server/_sweep.py                  # bindings + who has focus right now
python server/_sweep.py --watch          # just tail the log (no input)
python server/_sweep.py --state          # classify the current screen and exit
python server/_sweep.py --calibrate      # learn the difficulty/keymode keys
python server/_sweep.py --limit 600      # walk the list, one entry per song
python server/_sweep.py --variant 5K:HD   # capture every song at one variant
python server/_sweep.py --keymodes 4K,5K --difficulties EZ,HD   # a cross product
python server/_sweep.py --variants       # every key mode x every difficulty
python server/_sweep.py --dry-run        # print the plan, send nothing
python server/_sweep.py --no-screen      # disable the screen classifier entirely
python server/_sweep.py --no-verify      # do not confirm the song select before advancing
python server/_sweep.py --no-smart       # do not skip variants already dumped
python server/_sweep.py --no-stop-on-wrap  # ignore the wrap/end checks
```

**Escape is only pressed when it is provably safe.** In the main menu `ESC` means
나가기 (leave), so a blind `Esc`-based resync can walk the game out of song select.
The sweep therefore only sends the pause-menu exit when the entry actually started a
song (a pattern request *and* a CDN body arrived, so the next state is loading or
gameplay — never a menu), or when it knows the previous entry started a song and never
came back (so we are inside its gameplay). On a missed request it now **classifies the
screen** (`server/_screen.py`): *gameplay/pause* means the previous song is still
running and the pause menu is safe; *main menu* means re-enter the focused card; *song
select* or *unknown* means `Up` + `Enter`, which is harmless in every state and
productive in the two that matter. Timings in `server/data/sweep_keys.json`:
`wait_for_request` 8 s (a request arrives 1–2 s after a real Enter, so a stumble fails
fast) and `after_start` 8 s (time from the request to gameplay before `Esc`).

### Screen-state classifier — `server/_screen.py`

The log says what the game *asked for*, not where the UI is, so the safety decision
above needs to see the screen. It is deliberately **not** OCR, and not pixel-perfect
template matching: the song select is semi-transparent UI over an animated BGA.

* The BGA is heavily **blurred**, so the UI is the only high-frequency content. Edge
  energy separates them even *through* a translucent panel (measured at 1920x1080: UI
  ROIs 3.7–5.4 mean |grad| vs 1.8 for the blurred field). Matching an *edge* patch
  survives alpha blending; matching an intensity patch does not.
* Translucent panels move with the background, so **temporal differencing fails**: the
  blurred field moved ~100/255 between frames while the *static* circular preview
  looked UI-stable. The classifier instead keys on **saturated, near-opaque accents**
  (the yellow play disk — ~4,500 px, left half only) and on edge structure.
* Capture is **focus-independent**: the game is XWayland, so `ffmpeg -f x11grab
  -window_id` reads its pixels. `niri msg action screenshot-window` only captures the
  *focused* window, and this desktop is focus-follows-mouse, which made it unusable
  while the sweep's terminal held focus.

```bash
python server/_screen.py --debug                 # features + annotated ROI map
python server/_screen.py --collect MAIN_MENU     # save an anchor for a state
python server/_screen.py --watch                 # classify continuously
python server/_screen.py --list                  # collected anchors
```

`classify()` applies a few measured scalar rules first (yellow play disk -> song select;
a near-black *fade* -> `TRANSITION` (a uniform frame has `mean_v` ~0 and
`edge_all` ~0, whereas real gameplay with the BGA at zero opacity still has the
playfield/HUD: `mean_v` ~24, `edge_all` ~2.4); then very dark -> gameplay; then the red
banner -> game over), and finally the nearest match over **localized edge probes** of the
collected `server/anchors/<STATE>/` frames. The probes are only screen-unique regions
(`center` and `upperleft`): the shared chrome (nav, hint bar) correlates ~0.99 between
every screen and would drown out differences, which is exactly why a whole-frame
signature collided. Measured max cross-state correlation is 0.10 (`center`) / 0.19
(`upperleft`), so a match below 0.5, or without a 0.15 lead, is reported as `UNKNOWN` and
the sweep takes the safe recovery. Leaving a state's own anchors out never produces a
false positive in testing.

Transitions are handled on both sides: a fade is `TRANSITION`, and `_sweep.screen_state()`
is **debounced** — it waits out `TRANSITION` and requires every other state to persist for
`screen_stable` seconds (default 2 s, since the fade effect is ~1.5 s) before it is
accepted, sampling every `screen_debounce` seconds (0.4) under an overall `screen_timeout`
(6 s). A single dark frame mid-fade therefore cannot decide the recovery. `--watch` prints
the *raw* per-frame classification (so it still shows `GAMEPLAY` on a mid-fade frame); the
debounce applies where it matters, in `_sweep.screen_state()`. `LOADING_SCREEN` is likewise
waited on, not acted on.

Anchors are git-ignored (they contain BGA art); collect your own with `--collect`, and
`--list` flags any `.json` that has no matching `.png` (inert — probes read the PNGs).
Currently `GAMEPLAY`, `GAME_OVER`, `LOADING_SCREEN`, `MAIN_MENU`, `PAUSE_MENU` and
`SONG_SELECT` are anchored; anything else falls through to the safe `UNKNOWN` recovery.

### Variants

By default the sweep captures whatever variant is selected and never touches the
difficulty or key mode. `--variant`, `--keymodes`/`--difficulties` or `--variants`
build a **plan** that is captured for each song *before* it advances:

| axis | keys | order |
|---|---|---|
| difficulty | `Left`/`Right` | EZ, NM, HD, SHD — `Left` **does not wrap** (it clamps at EZ) |
| key mode | `Tab` | 4K, 5K, 6K, 8K — `Tab` **wraps** back to 4K |

Selection is tracked, not guessed: both axes are seeded from the newest request in the
log and re-read from every captured request (the request JSON names `keymode`/
`levelmode`), so a wrap is stepped the short way and a mismatch prints a warning and
recalibrates. Difficulty is stepped directly from the tracked value, or clamped with
three `Left` presses when the start is unknown. Because `Tab` wraps and cannot be targeted
without a known start, an unknown key mode presses nothing and lets the next request seed
it.

```bash
python server/_sweep.py --variant 5K:HD                       # one variant, every song
python server/_sweep.py --keymodes 4K,5K --difficulties EZ,HD  # 4 variants per song
python server/_sweep.py --variants                             # all 16 per song
```

`--variants` is 16 entries per song (≈16x slower), and a song's `.ezi` is per-song or
per key-mode group, so the full cross product is only worth it when you actually want the
exact per-variant charts. `--variant` / the axis flags are the cheap way to fill a
gap (e.g. capture the whole list at 5K HD, then again at 4K EZ).

**It only captures what is missing.** After the first entry identifies the song (the
request names it), the sweep reads `extracted_charts/<song>/` and drops every plan entry
whose `.ez` already exists, so a song that already has 4K/5K/6K but not 8K runs only the
four 8K variants before advancing. One entry per song is always spent identifying it (the
title is only known from the request), but the rest are skipped — `--no-smart` disables it.

### How the loop uses the state

* **A slow load is not a miss.** On a missed request the loop classifies; if the screen is
  `LOADING_SCREEN`/`TRANSITION` it waits and re-waits for the request instead of counting a
  failure. A genuine miss then goes through `recover()`.
* **Leave gameplay as soon as it is safe.** Instead of always waiting `after_start` (8 s),
  it polls the screen and presses Escape once gameplay has been stable for
  `gameplay_stable` (1.5 s) — about 4 s earlier. `after_start` stays the cap, and a
  `--no-screen` run uses it directly.
* **Start the variant keys early.** After the exit sequence it waits `after_exit` (1.2 s)
  and, if the screen is mid-transition, proceeds after `variant_lead` (0.5 s) rather than
  waiting for the debounced song select; the difficulty/key-mode keys land during the
  fade-in.
* **Confirm before advancing.** After leaving a song the loop calls `ensure_song_select()`:
  a cheap single-frame check first, then the debounced classifier if that is inconclusive.
  If it is not at the song select it acts (`MAIN_MENU` -> confirm the card,
  `GAMEPLAY`/`PAUSE_MENU` -> `resync`, `LOADING`/`TRANSITION` -> wait, else the harmless
  `Up`+`Enter`), and only advances once the state says song select. `--no-verify` skips it.
* **Stop when the list ends.** The list wraps (or `Down` clamps), so the loop stops when it
  comes back to the run's first entry, or when the same entry repeats three times in a row
  (`next_song` not advancing). `--no-stop-on-wrap` skips both checks.

A chart only counts as captured once the CDN body actually arrived: the sweep
watches for the addon's `CDN OK`/`CDN HIT` line and otherwise reports *asked but
no chart* and leaves the song on the to-do list (so a failed download can never
silently inflate coverage).

`--calibrate [--write]` is the interesting one: it enters a song, reads
song/keymode/levelmode back out of the request JSON, backs out, presses one candidate
key, and enters again — whatever changed is what that key does. So the bindings are
*derived*, not guessed, and `--write` stores them in `server/data/sweep_keys.json`.

The bindings were confirmed in game (note that the bottom hint bar labels the two arrow
pairs with icons that read the other way round — up/down is the song, left/right the
difficulty):

| screen | keys |
|---|---|
| song select (BASIC and STANDARD are the same layout — different colours, and a big rotated `<4/5/6/8K><MODE>` label) | `TAB` = key mode (4B/5B/6B/8B), **`Up`/`Down` = song, `Left`/`Right` = difficulty**, `SPACE` = equipment, `F1` = replay, **`Enter` = decide/start** (the hint bar also shows `SHIFT`), `ESC` = leave |
| list jumps | `0`–`9` section, `PageUp/PageDown` 8 rows, `a`–`z` by initial, `F6` random, `L/R SHIFT` = sort/version tabs |
| main menu | a **wrapping** card ring — BASIC, STANDARD, MULTIPLAYER, COURSE, LOUNGE, OPTION — arrow-navigated (`Left` from BASIC wraps to OPTION, so never spam a direction; `--mode` steps the short way and verifies) |
| after starting a song | loading screen → gameplay → **`Esc` opens PAUSE with RESUME focused → `Up` wraps to MUSIC SELECT → `Enter` confirms** → back at song select. That is the capture loop: it never plays a song to the end |
| pause menu | `Enter` = 결정 (confirm) — also the key that starts a song (the song select's hint bar additionally shows `SHIFT` as 결정) |

Screenshot tell: the **keyboard-focused** card's label panel is in saturated mode colours;
a mouse-hovered one is only a faint grey lift. For mode coverage run the sweep once per
mode (`--mode STANDARD --from BASIC`, then the default) — `gamemode` changes the chart
for the EZ~NM patterns of high-level songs, and the sweep checks the switch took by
comparing the next request's `gamemode` with the previous one.
Note `gamemode` (BASIC 1 / STANDARD 2) is a real chart selector for some songs —
recorded per capture, and worth preferring on serve once the captures carry it.

BASIC vs STANDARD, for reference: KOOL window 40 ms vs 22 ms, and for STANDARD
charts at level ≥6 (4K) / ≥8 (5K/6K) / ≥11 (DLC) the EZ~NM patterns are replaced
by easier BASIC-exclusive ones (HD/SHD unchanged; a few named exceptions).
Source: NamuWiki "EZ2ON REBOOT : R/시스템". `_coverage.py --log` is how a capture macro's progress is
verified without watching the screen — the game's own request names the song,
keymode and difficulty.

### Where the blocker lives (from the code)

`8CN26` is raised inside the song-load coroutine `ft.MoveNext`
(`0x6ffff2fa7327`) via the reporter `InGameCore.dci` (`0x6ffff2e87ec0`), with two
strings resolved by `oj.UI` (indices 166/167). `dci` is also the only writer of
the latch at `InGameCore+0x798`, which `ft.MoveNext` checks to decide whether to
abort — so the code is a **timeout inside the coroutine's wait**, not a verdict
from anywhere else, and the network is not involved (a failing load opens exactly
one connection: the handshake-only TLS probe to `3.37.247.33:443`). What the wait
depends on is the `bundleCryptKey` check (AGENTS.md §3.2); the code trail is kept
here for anyone chasing the exact step.

### The token (solved) and the key (open)

The client's token comparison is **local** and the token is a **session-key
knowledge proof** — the server proves it knows the client's live key by
AES-encrypting a fixed 32-byte client constant; the client decrypts and compares
with its own single `byte[32]` copy. `_pserver.py` mints the token itself, so
no official response is needed. The full account, including why the earlier
"the client owns no independent copy / the server audits out-of-band" reading was
wrong, is in **AGENTS.md §3.2 and §3.7**.

The one genuinely open item is how the *official* server learns the session key:
the working hypothesis is RSA in `c2s_login.data` (the login response is AES and
must be decryptable by the server, and our offline server — which runs no battle
handshake — is accepted), with the raw packet channel's `sendaes,` packet as the
battle server's copy. See AGENTS.md §3.1 and §7.6.

## Known simplifications / next steps

* `c2s_set_game_clear` and `c2s_get_userinfo` **shapes are known now** (AGENTS.md
  §3.2): the former is `{level, exp, nextExp, result}` (which is exactly the 48-byte
  / 64-char captured body), the latter `{memberinfo:[{STEAM_ID, LEVEL, RATING}],
  result}`. The missing part is *values*, not shape: `LEVEL`/`RATING` are placeholders
  until the per-user store lands, and the official bytes can no longer be decrypted
  (the session key rotated and was never kept).
* **The session key is Frida-free, and the login hand-off is solved.** The
  `version.dll` patcher rewrites `zf.publicKey` in-process, so the login block's RSA
  plaintext is the client's `{steamid,appid,version,key,iv}` JSON; `_pserver.py`
  decodes it (key, IV **and** SteamID) on every `c2s_login`. No harvester, no scan.
  The memory scanner `_harvest_mem.py` remains for an unpatched client. (The earlier
  "the RSA swap is not needed / cannot work" reading was wrong twice over: a
  *host-side* patch is too late because the provider is cached at `zf` static-init,
  but the in-process DLL beats it; and `cryptography`'s PKCS#1 v1.5 `decrypt` was not
  a valid oracle, so past "successes" were noise.) For a public server, distribute a
  DLL built against that server's public key; the raw-channel `sendaes,` hand-off is
  the alternative but is moot for the API.
* Rank endpoints accept any signature; nothing is verified or persisted.
* Songs without a captured chart fail at chart load (`result:0`) — extend
  coverage with `dump_song.py` and re-run `_build_data.py`.
* **Fully offline loads work** with no official contact (see above). The bCK
  constant is a value of a particular client build: after a game update, re-derive
  it by decrypting a captured token (that is `bck_payload()`'s fallback), or just
  re-check `server/data/bck_payload.hex`. Its *purpose* is now known (a session-key
  knowledge proof); its *preimage* is not, and does not matter.
