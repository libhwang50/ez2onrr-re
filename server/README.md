# EZ2ON REBOOT:R — basic private server

A first working private-server implementation for the Standard/Basic online
flow. It stubs the game's three HTTPS hosts entirely server-side and keeps the
raw-TCP channels (battle/control, raw IPs) pointed at the real servers.

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
pool; see `AGENTS.md` §3.7). With a wrong bCK the load simply never completes and
a watchdog reports it.

### The knobs and what they proved

```bash
python server/_exp.py                 # show state
python server/_exp.py hybrid on       # forward login+pattern upstream (harvest a token)
python server/_exp.py urls now        # mint our own Expires = now+150
python server/_exp.py bck harvested   # reuse the token from the last official response
python server/_exp.py off             # clear the url/bck mutations (hybrid untouched)
python server/_exp.py reset           # clear everything
```

| run | knob | result | conclusion |
|---|---|---|---|
| A | none (hybrid) | loads | baseline |
| B | `bck garbage` | 8CN26 | `bundleCryptKey` **is** acted on |
| C | `urls skew` (`Expires` +1 s → invalid signature) | **loads** | the URL signature is **never** verified |
| D/E | `urls future` / `expire` | fail | only because the bCK was stale, not because of the URL |

### The offline recipe

One official contact per session, only to obtain the token:

```bash
# 1. arm the harvester + server, then do ONE hybrid load to learn the token
.venv/bin/python server/_harvest_session.py          # terminal 1
python server/_exp.py hybrid on
mitmdump -s server/_pserver.py -w ./mitm_parsed/flow_dump_harvest   # terminal 2
#    launch the game, log in, enter one song → server/data/last_upstream_c2s_get_pattern_file.full.json

# 2. go fully offline (no official login, no passthrough, no CloudFront)
python server/_exp.py hybrid off
python server/_exp.py urls now
python server/_exp.py bck harvested
#    every song entry now loads with: our login, our music list, our profile,
#    our minted URL, our cached CDN files, the captured token
```

Verified by decrypting the response the client accepted: our URL path,
`Expires = now+150`, a *stale* signature, and the official token.

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
* **Fully offline loads work** (see above) but need one token per session, captured
  from a single official pattern response (`bck harvested`). What the client does
  with that token is still unknown — it keeps no local copy and opens no socket at
  load time, so it must be used as a key inside the load pipeline; the trail is
  written up in `AGENTS.md` §3.7 / §7.8. Until that is cracked, the fully offline
  mode is: one hybrid load to harvest, then pure private with `urls now` +
  `bck harvested`.
* The session key still requires the Frida bridge (and, in hybrid mode, so does
  the token). Patching `zf.gnf` to a fixed key and the token question are the two
  routes to a bridge-free server.
