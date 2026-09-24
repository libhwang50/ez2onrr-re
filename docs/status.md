# 7. Status & next steps

> Part of the EZ2ON REBOOT:R technical report — index: [docs/README.md](README.md).

**No blockers.** Every layer is solved: AssetBundles, keysounds/BGA, the API session
cipher, the CDN chart/index cipher (§3.3, `ripper/decrypt_chart.py`), and the pattern-response
token (`bundleCryptKey`, §3.2) — so the private server serves songs with **no official
server contact at all**.

**Done:** located the chart decryptor by scanning for direct calls into the `dc*` cluster
(`tools/il2cpp/_callers.js`), identified `dcf → dcg` as `mask ∘ AES-256-CBC`, extracted the
static key material (`svq`/`svr` mask tables, three key/IV pairs), and verified the result
end-to-end (5 songs, 3 key pairs). The 4K lane map and the long-note rule are verified
against the game's own `normalLanes`, 12/12 lanes exact. `ripper/parse_chart.py` reads the result:
header, tracks, note events with normal/long, `.ezi` join; JSON or a note listing.
`ripper/dump_song.py` now decrypts on capture and waits for the parse before snapshotting.
The login/session-key protocol is fully mapped (§3.1) and the private server (`server/`)
serves a complete online session — login, music list, profile, pattern files, CDN charts,
rank stubs. **Chart loads are fully offline**: the only thing taken from the running game
is its session key (which the client never puts on the wire), and the `bundleCryptKey`
token is minted server-side from a client constant (§3.2), byte-identical to the official
server's. In-game validation of the server itself is in progress.

**Next:**

1. Identify note types 5/6/9 against `InGameCore`'s `specialNoteData` / `autoNoteData`.
2. Find the song *name* for a chart with no API label — the header name gives the variant
   (`5-hd`) but not the song, so `ripper/dump_song.py` still falls back to `song_<hash>` there.
   (`patternFileInfo` reads empty at capture time, which is what forces the API route.)
3. Determine whether the API's `keymode` ever disagrees with the header-name / lane-count
   key mode (7K unobserved; 8K seen as `8-ez` but no API label yet).
4. Find what selects the key pair (`svk`/`svm`/`svo`) — not the payload, the CDN path, or
   `bundleCryptKey`; all three are in wide use and some songs mix them across variants, so
   it looks like an authoring/build-time choice.
5. Capture a bridge-keyed session **of the real servers** (plain `mitmdump -w` **plus**
   `server/re/_harvest_session.py` running — the auto-reattach harvester makes the ordering
   irrelevant) to decrypt the real `c2s_set_game_clear` response (48/64 B, length varies)
   and the real `c2s_get_userinfo` response (≈832 B / 10 profiles). A first attempt
   captured the traffic but not the key — the API bodies of that dump are sealed. Also
   pins the constant `plf` fields (§3.7). The same session settles §3.1: RSA-decrypt
   `c2s_login.data` with the (swapped-in) private key, or at minimum pair a harvested
   key with its own login blob so the login can be tested directly.
6. **Make the server Frida-free — SOLVED, two ways (§3.1).** (a) The deployment
   path: the drop-in `version.dll` rewrites `zf.publicKey` in-process, and the login
   block's RSA plaintext is the client's `{steamid,appid,version,key,iv}` JSON — no
   harvester, no scan, and it also yields the identity. Under Proton the app-dir DLL
   needs `WINEDLLOVERRIDES=version=n,b`; on Windows it loads as-is. (b) The fallback:
   `server/re/_harvest_mem.py` scans the running game's memory for the transient
   `{"key":"<32hex>","iv":"<16hex>"}` JSON and writes `session_key.json`; no Frida,
   verified end-to-end. Remaining for a **remote/public** server: distribute a DLL
   built against that server's public key (per-server artifact), or keep the memory
   scan as a helper where the game runs. The raw-channel `sendaes,` hand-off is the
   second candidate key source but is now moot for the API.
7. Broaden chart coverage in `server/data/`. Measured: **158 of 601 songs** at the time
   of writing (the
   music list's 1,201 entries are two `GAME_MODE`s of the same songs, and gamemode is
   not a chart selector). Coverage is per *song*, because the server returns the CDN
   path — `chart any` serves a song's captured chart for any of its keymodes/
   difficulties. Adding songs needs one official pattern request each (hybrid,
   `chart exact`, walk the song list), the addon's recorded CDN bodies, then
   `_build_data.py`; `server/re/_coverage.py --log` verifies a capture run, and
   `server/re/_sweep.py` automates the walk (guarded by a focused-window check, with a
   `--calibrate` mode that learns the difficulty/keymode keys from the request JSON).
   Also record `gamemode` per capture (BASIC vs STANDARD differs by rule, §3.5). Uncaptured
   songs answer `result:0` and the client retries 5× against **our** server, so a miss
   is harmless.
8. **`bundleCryptKey` — SOLVED (§3.2/§3.7).** Fully offline chart loads are the
   server's **default**: a self-minted token, encrypting the client's build-time 32-byte
   payload constant (embedded as `DEFAULT_BCK_PAYLOAD` in `_pserver.py`) under the live
   session key, exactly as the official server does. Nothing comes from an official
   response any more. Remaining nicety: a game update can change the constant —
   re-derive it (a fresh capture or `server/data/bck_payload.hex` overrides).
9. Persist progression — **started**: `server/_store.py` (SQLite, `data/store.db`)
   keeps per-user `memberinfo` + `clearlist` (one row per cleared variant, rebuilt
   into the client's 16-wide arrays), seeded for the owner from the captured
   `myinfo.json` (319 variants). `c2s_set_game_clear` now records every play
   (best-of score, never downgrade the lamp, count plays) and `c2s_get_myinfo` /
   `c2s_get_userinfo` read it. Leaderboards are also computed from the store now
   (Top100 / MyRange), falling back to the captured `rank_csv/` only for a variant
   nobody here has played. The login response and `set_game_clear` are per-user —
   they no longer serve the captured owner's SteamID/level to other accounts.
   `server/_fake_client.py` creates a second user end-to-end (RSA login → play →
   leaderboard) with no second game install, so multi-user is testable locally.
   Still to do: feed the rank `plf…` uploads in too (the same data over the other
   host — its fields do not cleanly carry `levelmode`, so `set_game_clear` remains
   authoritative), and RE / implement the per-mode rating formula (the client
   computes it from this clearlist — §3.7). For a **public** server the claimed
   SteamID must not be trusted: issue a server-side identity token instead (a
   Steam emulator such as Goldberg lets account-less users play, but its identity
   is self-asserted), and every user must set a **unique** SteamID or the session
   registry and store collide.
10. Re-check the captions in the "8CN26" sections above when touching them: the code
   means "Song Load timeout" (a watchdog), NOT "corrupt file" — the Korean popup text
   ("게임 파일이 손상되었습니다") is the generic wrapper the reporter shows.
11. Public-server identity — **Phase 1 started**: a third party *cannot* verify the
   Steam auth ticket (`ISteamUserAuth/AuthenticateUserTicket` and `CheckAppOwnership`
   require the app **publisher's** Web API key), and the RSA pubkey-swap only proves
   the client runs our patcher — so the SteamID is not a credential.  Access is now a
   **server-issued bearer token** (`server/_auth.py`, `server/_accounts.py`, accounts
   table in `_store.py`): `auth.json` `mode` = `open` (default, the old behaviour) or
   `token`; a `guest` tier (`allow`/`deny`, `guest_persist`) is configurable; providers
   (Discord OAuth) are optional registration front ends only.  The account's public id
   is chosen at registration (real SteamID or a generated pseudo-SteamID) and the
   server overrides the login's claimed id with it; on the Goldberg path the launcher
   writes that id into the emulator config.  Still to do: the thin client relay +
   standalone ASGI server (so the token rides an `X-EZ2-Token` header instead of a local
   file), and optional Steam OpenID binding so a real SteamID can be *proven* rather
   than claimed.
12. Standalone server — **done**: the game handlers in `_pserver.py` are now
   transport-neutral (`_flowshim.py` supplies the few mitmproxy pieces they use and
   returns a real mitmproxy `Response` when it is importable; `mitmproxy` itself is
   an optional import).  `server/app.py` is a stdlib HTTP(S) server (TLS via
   `--cert`/`--key`, `/healthz`, plus an ASGI `asgi_app` for uvicorn/hypercorn) that
   routes by `X-EZ2-Host` or `Host`; `_core.handle(host,method,path,headers,body)` is
   the transport-free entry point.  The client side is a thin mitmproxy relay
   (`_relay.py`) that forwards each game host to the remote server with `X-EZ2-Host`
   and `X-EZ2-Token`.  Verified: in-process core (login→myinfo→rank→404), the HTTP
   server by `curl`, and the full path (`_fake_client` → relay:8082 → app:8081 →
   leaderboard), in open and token mode.  The addon path (`mitmdump -s
   server/_pserver.py`, the local single-machine setup) still works unchanged.
   Containerised for a homeserver (`Dockerfile`, `docker-compose.yml`, an
   optional Caddy profile): only `server/data` (rw: RSA key, templates,
   `store.db`, `auth.json`) and `extracted_charts` (ro) are mounted;
   `EZ2_LOG`/`EZ2_DATA` relocate those roots; `server/requirements.txt` is just
   `cryptography`.  Run one replica only — session keys are in memory.
