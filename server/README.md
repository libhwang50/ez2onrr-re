# EZ2ON REBOOT:R — basic private server

A first working private-server implementation for the Standard/Basic online
flow. It stubs the game's three HTTPS hosts entirely server-side and keeps the
raw-TCP channels (battle/control, raw IPs) pointed at the real servers.

**Chart loads work fully offline** (no official login, no CloudFront, no borrowed
token): the URL signature is never verified and `bundleCryptKey` is minted here —
it is AES-256-CBC/PKCS7 of a **client-side constant** under the client's live
session key. See "Fully offline chart loads" below.


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
  `BitConverter.ToString` → strip `-`) and never sent over HTTPS, so the server
  learns them from the running game via the Frida bridge (below).

**No upstream leakage.** An unhandled exception inside a mitmproxy addon hook
does not abort the request — mitmproxy forwards it to the real upstream. The
first test run therefore mixed real and private responses invisibly. The addon
now catches every failure on a game host and serves an explicit error instead;
a game-host request must never leak upstream. (Level/rating seen in-game during
a mixed session came from the real servers — with a clean run they come from
`data/profile.json`.)

Validated in-game (one session): login → music list → profile → Finite 5K HD
chart + `.ezi` served from cache → played → score upload logged. The leaderboard
profile fetch (`c2s_get_userinfo`, a list of up to ~10 SteamIDs) is the one
remaining shape guess — a wrong body makes the client pop a JSON parse error and
exit; tune `data/userinfo_entry.json` if that appears.

## Files

| file | purpose |
|---|---|
| `_pserver.py` | the mitmproxy addon (the server itself); logs to `pserver.log`; never forwards game-host traffic upstream |
| `_harvest_session.py` | Frida bridge: polls `zf.aes_key`/`aes_iv` at 1 Hz → `session_key.json`; **auto-re-attaches when the game restarts** (a stale key makes the client reject every response) |
| `_build_data.py` | (re)builds `data/` from the captured artefacts in the repo |
| `data/login.json` | `c2s_login` response template (real, captured) |
| `data/myinfo.json` | `c2s_get_myinfo` template — `clearlist`, `memberinfo`, … |
| `data/gameinfo.json` | `c2s_get_gameinfo` template — the 1,201-entry music list |
| `data/profile.json` | your member-field overrides (`NICKNAME`, `LEVEL`, …). Note: the in-game rating shown per key mode is **computed client-side** from your play data — `RATING` here only sets the myinfo field, not the displayed per-mode values |
| `data/charts.json` | (song, keymode, levelmode) → CDN paths, 47 variants / 15 songs |
| `data/cdn_paths.json` | CDN path → local ciphertext file (126 paths) |
| `data/rank_sample.csv` | fallback leaderboard body when no exact capture matches |
| `data/rank_csv/` | real leaderboard CSVs per query (Top100 / MyRange of captured songs), served exactly |
| `data/userinfo_entry.json` | one leaderboard-profile entry, cloned per requested SteamID (shape = best guess until a real capture) |
| `data/bundleCryptKey.txt` | value served as `bundleCryptKey` when no knob overrides it |
| `data/set_game_clear.json` | optional override for `c2s_set_game_clear` (default `{"result":1}`) |
| `data/mutate_urls.txt` / `data/mutate_bck.txt` | the experiment knobs written by `_exp.py` (read per request) |
| `data/passthrough_endpoints.txt` | endpoints forwarded upstream (hybrid mode), read per request |
| `data/last_upstream_*.json` / `…​.full.json` | the last decrypted upstream response (shortened / with real URLs+key) |
| `_exp.py` | control the experiment knobs from the shell (`hybrid`, `urls`, `bck`, `off`, `reset`) |
| `_mem.py` | drive the harvester's command channel: `findhex`, `findlea`, `findlit`, `findthunk`, `readbytes`, `bck` |
| `_stub443.py` | loop-proof TLS stub for the game's un-proxied 443 channel (mitmproxy-CA-signed cert) |
| `_stub9902.py` | capturing TCP relay for the raw audit channel; address comes from `data/battle_server.txt` |
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

```bash
# terminal 1 — session-key bridge (start once, leave running)
.venv/bin/python server/_harvest_session.py

# terminal 2 — the server
mitmdump -s server/_pserver.py
```

Then start the game normally. Watch `server/pserver.log`.

**Ordering no longer matters** — the harvester auto-re-attaches when the game
restarts, and the login handler waits up to 15 s for the key. Start the
harvester once and forget it. (The game generates its session key before the
login request; without a key the login can only fail — the client pops
"Object reference not set…" and OK quits the game, because a response
cannot be encrypted without the key.)

⚠ The harvester never attaches while the game is starting up: an attach during
the early startup window kills the process instantly (no crash handler). It
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

```bash
python server/_exp.py                 # show state
python server/_exp.py chart any       # serve a song's captured chart for any variant
python server/_exp.py chart exact     # only the exact keymode/difficulty (capturing)
python server/_exp.py hybrid off      # no passthrough to the official servers
python server/_exp.py urls now        # mint our own Expires = now+150
python server/_exp.py bck mint        # mint the token (client constant + live key)
python server/_exp.py bck mint:zero   # ... with a zero payload (diagnostic)
python server/_exp.py bck harvested   # or reuse the token from a captured response
python server/_exp.py off             # clear the url/bck mutations (hybrid untouched)
python server/_exp.py reset           # clear everything
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

No official contact at all — the protocol-level token is minted here:

```bash
.venv/bin/python server/_harvest_session.py   # terminal 1: keeps session_key.json live
mitmdump -s server/_pserver.py                # terminal 2: the server

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

`server/_sweep.py` automates that walk. It is **blind by design** — the server log
is its sensor, since every request names the song, keymode, levelmode and gamemode
— and it refuses to send keys unless the focused window really is the game
(`niri msg focused-window`), so it cannot type into your terminal.

```bash
python server/_sweep.py                  # bindings + who has focus right now
python server/_sweep.py --watch          # just tail the log (no input)
python server/_sweep.py --calibrate      # learn the difficulty/keymode keys
python server/_sweep.py --limit 600      # walk the list, one entry per song
python server/_sweep.py --variants       # also cycle difficulty/keymode
python server/_sweep.py --dry-run        # print the plan, send nothing
```

**Escape is only pressed when it is provably safe.** In the main menu `ESC` means
나가기 (leave), so a blind `Esc`-based resync can walk the game out of song select.
The sweep therefore only sends the pause-menu exit when the entry actually started a
song (a pattern request *and* a CDN body arrived, so the next state is loading or
gameplay — never a menu), or when it knows the previous entry started a song and never
came back (so we are inside its gameplay). When it does not know where it is, the
recovery is `Up` + `Enter`, which is harmless in every state and productive in the
two that matter: in song select it starts a song, in the main menu it re-enters the
focused card. Timings in `server/data/sweep_keys.json`: `wait_for_request` 8 s (a
request arrives 1–2 s after a real Enter, so a stumble fails fast) and `after_start`
8 s (time from the request to gameplay before `Esc`).

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
Source: NamuWiki "EZ2ON REBOOT : R/시스템". Then `_exp.py offline` serves them
with `chart any`. `_coverage.py --log` is how a capture macro's progress is
verified without watching the screen — the game's own request names the song,
keymode and difficulty.

### Where the blocker lives (from the code)

`8CN26` is raised inside the song-load coroutine `ft.MoveNext`
(`0x6ffff2fa7327`) via the reporter `InGameCore.dci` (`0x6ffff2e87ec0`), with two
strings resolved by `oj.UI` (indices 166/167). `dci` is also the only writer of
the latch at `InGameCore+0x798`, which `ft.MoveNext` checks to decide whether to
abort — so the code is a **timeout inside the coroutine's wait**, not a verdict
from anywhere else, and the network is not involved (a failing load opens exactly
one connection: the handshake-only TLS probe to `3.37.247.33:443`).

The remaining question is *what that wait depends on* — i.e. which step of the
load pipeline the `bundleCryptKey` feeds. Leads for anyone resuming:
the strings at `oj.UI(166)`/`oj.UI(167)` (they label the failed step); the wait
loop inside `ft.MoveNext` around the two latch checks
(`0x6ffff2fa71c2`/`0x6ffff2fa7205`); and a field-by-field diff of the
`InGameCore` instance (fields live at 0x510-0x840, §4.3 of `AGENTS.md`) between a
successful load and a failing one.

### What is still unknown

The client owns no local copy of the token (a full-heap scan finds exactly two
copies, both derived from the response — no independent copy, no base64 copy in
UTF-8 or UTF-16) and opens no socket at load time (443 probes are handshake-only,
4649 carries ping/pong, 9902 is never dialled — even when our stub is the
`get_battle_server_ip` it is served). Tested and rejected as derivations:
SHA-384/512, HMAC and AES combinations over the session key, the Steam ticket,
the login ciphertext, the SteamID. So it is *used as a key* somewhere in the load
pipeline and the silent failure is what times out. The trail forward
(`findhex`/`findlea`/`findthunk`, the literal-keyed runtime hash tables, `da.rus`'s
hand-off) is described in `AGENTS.md` §3.7 and §7.8.

## Known simplifications / next steps

* `c2s_set_game_clear` response is a guess (`{"result":1}`); the real body is
  48 B of ciphertext — capture one session against the **real** servers with the
  bridge running (plain `mitmdump -w`, addon disabled) to fill
  `data/set_game_clear.json`.
* `c2s_get_userinfo` serves a **guessed list shape** (`data/userinfo_entry.json`
  cloned per requested SteamID); a wrong shape makes the client pop its JSON
  parse error — screenshot it if you see it, it names the expected type.
* The session key still requires the Frida bridge. Long-term options: patch
  `zf.gnf` to a fixed key, or RE the TCP control channel (where the real
  server presumably learns the key).
* Rank endpoints accept any signature; nothing is verified or persisted.
* Songs without a captured chart fail at chart load (`result:0`) — extend
  coverage with `dump_song.py` and re-run `_build_data.py`.
* **Fully offline loads work** with no official contact (see above). The bCK
  constant is a value of a particular client build: after a game update, re-derive
  it by decrypting a captured token (that is `bck_payload()`'s fallback), or just
  re-check `server/data/bck_payload.hex`. Its *purpose* is now known (a session-key
  knowledge proof); its *preimage* is not, and does not matter.
* The session key still requires the Frida bridge — it is generated in the client
  and never sent, so a bridge-free server would need `zf.gnf` patched or the raw
  TCP channel RE'd. This is the last dependency on Frida.
