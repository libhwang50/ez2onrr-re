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

* API **request**  = `data=` + urlenc(b64( magic`d3ad76d3adb8` ‖ AES-CBC-PKCS7(json) ))
* API **response** = b64( AES-CBC-PKCS7(json) )
* key/IV = the ASCII bytes of `zf.aes_key` / `zf.aes_iv` — generated
  **client-side** per session (`zf.gnf`: `RNGCryptoServiceProvider` →
  `BitConverter.ToString` → strip `-`) and never sent over HTTPS, so the server
  learns them from the running game via the Frida bridge (below).

## Files

| file | purpose |
|---|---|
| `_pserver.py` | the mitmproxy addon (the server itself); logs to `pserver.log` |
| `_harvest_session.py` | Frida bridge: polls `zf.aes_key`/`aes_iv` at 1 Hz → `session_key.json` |
| `_build_data.py` | (re)builds `data/` from the captured artefacts in the repo |
| `data/login.json` | `c2s_login` response template (real, captured) |
| `data/myinfo.json` | `c2s_get_myinfo` template — `clearlist`, `memberinfo`, … |
| `data/gameinfo.json` | `c2s_get_gameinfo` template — the 1,201-entry music list |
| `data/profile.json` | your member-field overrides (`NICKNAME`, `LEVEL`, `RATING`, …) |
| `data/charts.json` | (song, keymode, levelmode) → CDN paths, 47 variants / 15 songs |
| `data/cdn_paths.json` | CDN path → local ciphertext file (126 paths) |
| `data/rank_sample.csv` | leaderboard body served for `get<id><km><lm>,<page>` |
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
* The harvester deletes a stale `session_key.json` on startup, so always start
  it before the game.
* Only songs with a captured chart are playable (see `charts.json`); other
  songs fail at chart load with `result:0`. Add more by running
  `dump_song.py`/captures and re-running `_build_data.py`.
* Score uploads (`plf…`) are logged but stored nowhere yet; the leaderboard
  served is a static sample.

## Known simplifications / next steps

* `c2s_set_game_clear` response is a guess (`{"result":1}`); the real body is
  48 B of ciphertext — capture one session with the bridge running to fill
  `data/set_game_clear.json`.
* `c2s_get_userinfo` always serves your own profile (leaderboard profile views
  show you).
* The session key still requires the Frida bridge. Long-term options: patch
  `zf.gnf` to a fixed key, or RE the TCP control channel (where the real
  server presumably learns the key).
* Rank endpoints accept any signature; nothing is verified or persisted.
* Songs without a captured chart fail at chart load (`result:0`) — extend
  coverage with `dump_song.py` and re-run `_build_data.py`.
