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
| `data/profile.json` | your member-field overrides (`NICKNAME`, `LEVEL`, `RATING`, …) |
| `data/charts.json` | (song, keymode, levelmode) → CDN paths, 47 variants / 15 songs |
| `data/cdn_paths.json` | CDN path → local ciphertext file (126 paths) |
| `data/rank_sample.csv` | leaderboard body served for `get<id><km><lm>,<page>` |
| `data/userinfo_entry.json` | one leaderboard-profile entry, cloned per requested SteamID (shape = best guess until a real capture) |
| `data/bundleCryptKey.txt` | value served as `bundleCryptKey` (transport/audit record, §4.2) |
| `data/set_game_clear.json` | optional override for `c2s_set_game_clear` (default `{"result":1}`) |

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
# terminal 1 — session-key bridge (before starting the game!)
.venv/bin/python server/_harvest_session.py

# terminal 2 — the server
mitmdump -s server/_pserver.py
```

Then start the game normally. Watch `server/pserver.log`.

Notes:

* The Wine proxy must point at the mitmdump instance (`ProxyEnable=1`,
  `ProxyServer=127.0.0.1:8080`) — the same setting used for every capture so far.
* The harvester deletes a stale `session_key.json` on startup and re-attaches
  when the game restarts — start it once and leave it running.
* Pattern lookup is **exact-match only** (song + keymode + levelmode): serving a
  different difficulty's chart would load wrong notes. Uncaptured songs fail
  with `result:0`; the client retries 5× then boots to the main screen.
* Only songs with a captured chart are playable (see `charts.json`); add more by
  running `dump_song.py`/captures and re-running `_build_data.py`.
* Score uploads (`plf…`) are logged but stored nowhere yet; the leaderboard
  served is a static sample.

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
