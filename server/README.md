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

## Fully-offline chart loads: the mutation experiments

the 8CN26 check is *post-parse*: the client has the chart downloaded, decrypted
and parsed, then rejects the session. A fresh upstream pattern response loads;
a replayed (stale) or synthesized one does not. To find out *which part* of the
response is validated, mutate a known-good response in flight.

Knobs are ordinary files in `server/data/`, re-read on **every** response, so an
experiment needs no mitmdump restart (only turning `passthrough_pattern` on/off
does):

| file | value | effect |
|---|---|---|
| `mutate_urls.txt` | `future` | `Expires` +10 years — signature no longer matches |
| | `expire` | `Expires` in the past — signature still valid |
| | `noparams` | strip the whole query string |
| | `host` | swap the CDN host, keep path/params |
| `mutate_bck.txt` | `stale` | the older captured real `bundleCryptKey` |
| | `garbage` | 48 random bytes, valid base64 shape |
| | `empty` | the field emptied |
| | `literal:<b64>` | any exact value |

Both mutations apply to a **passthrough** (fresh upstream) response *and* to a
**replayed** one, so the decisive test can be run without an official login:

```bash
# experiment 1 — replayed (stale) response, only the expiry made "fresh"
rm -f server/data/passthrough_pattern
echo future > server/data/mutate_urls.txt
mitmdump -q -s server/_pserver.py        # enter the song
```

`pserver.log` shows `MUTATED (replayed): ['final_url_ez=future', …]`. Delete the
knob file to return to the untouched response.

How to read the results:

* **replay + `future` loads** → the client does not verify the CloudFront
  signature, and the stale `bundleCryptKey` is not the blocker either. Then a
  fully offline server just needs plausible far-future URLs.
* **replay + `future` fails, passthrough + `future` loads** → the signature is
  not verified but something else about a *replayed* response is wrong —
  `bundleCryptKey`, or the upstream-minted URL's path/params.
* **passthrough + `future` fails** → the client *does* verify the CloudFront
  signature; a fully offline server then needs the embedded public key
  (a hunt) or a client patch.
* **passthrough + `garbage` loads** → `bundleCryptKey` is not validated at all.
* **passthrough + `expire` loads** → the knob is not reaching the response (or
  expiry genuinely is not checked) — investigate before trusting any result.

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
