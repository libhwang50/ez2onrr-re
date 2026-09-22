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

Use `server/_exp.py` (knobs are re-read on **every** response, so nothing needs
a restart):

```bash
python server/_exp.py                    # show the current state
python server/_exp.py hybrid on          # forward login+pattern upstream
python server/_exp.py urls future        # Expires +10y (breaks the signature)
python server/_exp.py bck garbage        # 48 random bytes
python server/_exp.py off                # everything back to private
```

⚠ `python server/_exp.py off` clears the **url/bck mutations only** — the hybrid
setting is untouched. Use `hybrid off` for that, `reset` for everything. (It used
to clear the endpoints too, which silently turned a mutation test back into a
replay test — check `pserver.log`: a valid upstream test logs `UPSTREAM
c2s_get_pattern_file: …`, a replay test logs `REPLAYED official response`.)

⚠ **The Frida harvester must be running** (`.venv/bin/python
server/_harvest_session.py`) even in hybrid mode: forwarding the login upstream
gets the *upstream* session working, but this addon still has to encrypt its own
stub responses (`c2s_get_gameinfo`, `c2s_get_myinfo`) with the client's
per-session key. Without it the addon answers `502 no session key` and the game
shows `RESULT : TD3 HTTP/1.1 502 Bad Gateway`. The alternative, if no bridge is
wanted, is to forward those endpoints too:
`passthrough_endpoints.txt = login,gameinfo,myinfo,pattern`.

| knob | value | effect |
|---|---|---|
| `urls` | `skew` | `Expires` +1 s — still "fresh", but the signature no longer matches |
| | `future` | `Expires` +10 years — signature no longer matches |
| | `expire` | `Expires` in the past — signature still valid |
| | `noparams` | strip the whole query string |
| | `host` | swap the CDN host, keep path/params |
| `bck` | `stale` | the older captured real `bundleCryptKey` |
| | `garbage` | 48 random bytes, valid base64 shape |
| | `empty` | the field emptied |
| | `literal:<b64>` | any exact value |

Both mutations apply to a **passthrough** (fresh upstream) response *and* to a
**replayed** one, so a decisive test can be run without an official login.

### Two experiments already done

* **replay + `urls future` → 8CN26.** Both CDN files were downloaded successfully
  (served from our cache) and the load still failed, so the check is neither a
  pre-download URL rejection nor a download failure — it happens after parse.
* **`hybrid` off + knobs set → `{"result":0}` from upstream** (24 B) → the client
  retries the download 5× and shows `ErrCode: GPF 5 TIMES FAILED`. A forwarded
  pattern request is meaningless unless the **login** was forwarded too — the
  real server has no session to mint URLs for. Hence `hybrid on` = `login,pattern`.

### The discriminating tests (one hybrid session, one entry each)

With `hybrid on` and an official login in the same instance:

| run | knob | loads | fails 8CN26 | conclusion |
|---|---|---|---|---|
| A | none | ✓ | | control — hybrid works |
| B | `bck garbage` | | | `bundleCryptKey` is **not** validated |
| C | `urls skew` | | | **no signature verification** — an offline server may mint its own URLs (any fresh-looking `Expires`) |
| D | `urls future` | | | signature **is** checked → need the embedded public key (or the check is an `Expires` window) |
| E | `urls expire` | | | expiry is a real check |

`skew` (`Expires` +1 s) is the decisive one: the URL still looks perfectly fresh
to any expiry-window check, but its CloudFront signature is invalid. It separates
"the signature is verified" from "the URL just has to look recent". `future`
(+10 years) fails under *both* explanations, so it cannot separate them on its
own.

`pserver.log` logs every upstream response it decrypted
(`UPSTREAM c2s_get_pattern_file: {result=1, final_url_ez=…, …}` plus each URL's
path/`Expires`/signature length) and saves it to
`data/last_upstream_c2s_get_pattern_file.json` (shortened) and
`…​.full.json` (real URLs + key, git-ignored) — so a known-good response can be
diffed against the replay and reused.

## The raw channel — where the `bundleCryptKey` is actually checked

The mutation matrix settled the two open questions:

* **CloudFront URL signature: not verified.** `urls skew` (`Expires` +1 s, so the
  signature no longer matches, while the URL still looks perfectly fresh) **loads
  and plays**. So a private server may mint its own URLs with any plausible
  `Expires` and a shape-valid signature.
* **`bundleCryptKey`: validated.** `bck garbage` against a fresh, correctly
  signed upstream response (48 random bytes, same base64 shape) **fails with
  8CN26**. It is therefore the *only* thing about the pattern response the client
  checks. It is not derived from the session key (SHA-384/HMAC/AES against
  `zf.aes_key`/`aes_iv` and the unused `bbk.wdp`/`wdq` static pair all miss), so it
  is server-minted random data.

Where can it be checked, if not over the proxied HTTP? A `tcpdump` of a
successful hybrid load (`host 3.37.247.33`) shows, besides the documented
`websocket-sharp` Notice channel on **4649** (verified again: `GET /Notice?id=…`,
`101`, then ping/pong — no audit payload, and no port **9902** traffic at all),
about **nine direct TLS connections to `game1-rank.ez2game.co.kr:443`** whose
`Sectigo *.ez2game.co.kr` certificate and `1562`-byte ClientHello are followed by
an encrypted request and no plaintext HTTP — and they cluster **right before the
chart load**. They are *not* mitmproxy's: with the addon stubbing the rank host,
mitmproxy provably never dials upstream (verified with a local request through a
second instance: the addon answers `3.37.247.33:9902` with no `server connect`).
So the game uses a **second, custom TLS client that ignores the WinHTTP proxy**,
and *that* is the one channel no amount of addon stubbing has ever touched. The
`bundleCryptKey` verdict matches its timing exactly.

Interception harness — redirects both the hostname and the raw IP to
`server/_stub443.py`, a small **loop-proof** TLS stub that signs its certificate
with the user's mitmproxy CA, logs every request byte-for-byte, and never
connects upstream:

```bash
sudo server/_rawchannel.sh on      # hosts entry + iptables REDIRECT + stub on 443
sudo server/_rawchannel.sh test    # self-test; should print 3.37.247.33:9902
# now relaunch the game, log in, load a song, then:
sudo server/_rawchannel.sh status  # redirect state, matched-packet count, stub log
tail -40 server/stub443.log
sudo server/_rawchannel.sh off     # stub down, hosts + iptables restored
```

⚠ Do **not** use mitmproxy in reverse mode for this. With the hostname redirected
to 127.0.0.1, a reverse proxy resolves its own upstream to 127.0.0.1, so every
request it does not intercept opens a connection to itself: an escalating loop
that ends in `OSError: [Errno 24] Too many open files` and a hung client. (First
attempt did exactly that.) A stub that never dials upstream cannot loop.

If the client accepts the CA-signed certificate (likely — the same Wine trust
store already validates it for the proxied hosts) the requests become readable
and a fully-offline server is a matter of answering them. If the handshake is
rejected (`TLS FAILED ... in stub443.log`) the client pins its own CA bundle and
the next step is to find and extend that bundle.

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
