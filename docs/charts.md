# 3. Chart delivery — API cipher & DTOs

> Part of the EZ2ON REBOOT:R technical report — index: [docs/README.md](README.md).

Charts are **not** in the client. On song entry `InGameCore` calls the HTTPS API,
receives signed CDN URLs, then downloads and decrypts locally with a **static** key
baked into the binary (§3.3).

| | |
|---|---|
| API | `https://game1-play.ez2game.co.kr/api/` (test host `game1-test99…`) |
| Rank | `https://game1-rank.ez2game.co.kr/` — plaintext `GET ?data=…`: leaderboards, score upload, battle-server lookup (§3.7) |
| CDN | CloudFront `game1-cdn.ez2game.co.kr` (`Key-Pair-Id=K2L5B5JS5W46ST`); signed URLs with a **~150 s TTL** |
| Transport | WinHTTP. `mitmproxy` sees everything (Wine prefix has `ProxyEnable=1`, `ProxyServer=127.0.0.1:8080`) |
| Control channel | proprietary TCP to `3.37.247.33:4649`, `zf` RSA+AES — not needed for extraction |

### 3.1 API session cipher — CRACKED

Bodies are `data=<base64>` (request) / raw base64 (response) around **AES-CBC / PKCS7**.

* **Key** = the **32 ASCII bytes** of `zf.aes_key` (not hex-decoded); **IV** = the
  **16 ASCII bytes** of `zf.aes_iv`.
* **The client generates both itself, and they rotate *within* a launch** *(supersedes
  both "overwritten at login" and the later "per launch")*: `zf.gnf()` draws 32/16 bytes
  from `RNGCryptoServiceProvider` and hex-encodes them (`BitConverter.ToString` → strip
  `-`; uppercase). Observed in a single launch: `6440E3ED…/8044B641…` at 16:08 →
  `316A60CA…/6B4716FE…` at 16:27. So anything that needs the key must **re-read it per
  request** — which is why the harvester rewrites `server/session_key.json` at 1 Hz and
  `_pserver.py` reads it per request. Pre-generation
  defaults are the metadata placeholders `01234567890123456789012345678901` /
  `0123456789012345`. Read the live values with `il2cpp_field_static_get_value`, never
  the metadata defaults.
* **How the server learns the AES key** *(2026-09-23; the earlier “`data` =
  `RSA("")`” reading is superseded — PKCS#1 v1.5 **encryption** is randomized, so a
  re-encryption byte-match can neither prove nor disprove an empty plaintext, and all
  7 captured login blobs differ).* The login request has exactly three fields:
  `data`, `ticket=<Steam auth session ticket, hex>` and `identity=<SteamID>`, so `data`
  is the only carrier. It is exactly one 2048-bit RSA block (256 B) and
  `zf.publicKey` is the baked-in 2048-bit server key (`<RSAKeyValue>` literal;
  `zf` = `WebManager`), with `zf.RSAEncrypt`/`RSADecrypt`/`CreateRSAKey` present. The
  protocol forces the server to already know the key when it replies (**the login
  *response* is b64 AES-CBC, and our fully-offline server — which never runs a battle
  handshake — encrypts it under the harvested key and is accepted**), and the carrier
  is **`data` = RSA(login JSON) under `zf.publicKey`**, the official server holding the
  private half — **SOLVED 2026-09-24** (the JSON carries `key`/`iv`/`steamid`; see the
  RSA-hand-off bullet below). A second hand-off exists for the battle/multiplayer
  server holding the private half. A second hand-off exists for the battle/multiplayer
  server: the `sendaes,` packet (literals `[9903]sendKeyDataStr:`, `[AES 키 전송
  완료]`, acked by `s2c_aes_connect_completed`) on the raw packet channel
  (`aes,<command>[,<args>]` framing, addressed by `get_battle_server_ip` →
  `3.37.247.33:9902`). Its necessity is now moot for the API (§3.1 below).
* **RSA hand-off — SOLVED (2026-09-24).** Strict raw-RSA decode of `c2s_login.data`
  yields the **141-byte login JSON**
  `{"steamid":"…","appid":"1477590","version":"2026.09.04.001","key":"<32
  hex>","iv":"<16 hex>"}`, whose `key`/`iv` match `re/_harvest_mem.py`'s independent
  read byte-for-byte. Nothing is borrowed from an official server: the drop-in
  `version.dll` (`client/patcher/`) rewrites the live `zf.publicKey` literal to the
  private server's key, and `server/_rsa.py` decrypts the block. Two things had hidden
  this:
  * **The patch must land before `zf`'s static ctor.** The DLL is loaded in-process at
    startup (and the patcher thread polls from then on), which beats the cached
    `RSACryptoServiceProvider`; a *host-side* patch after launch is too late — that is
    why an earlier attempt concluded the swap "is not needed". Under Proton the
    app-dir `version.dll` is ignored (Wine loads its own builtin) unless
    `WINEDLLOVERRIDES=version=n,b` is in the Steam launch options; on Windows it loads
    without it.
  * **`_rsa.decrypt` was not a real oracle.** `cryptography` 48's PKCS#1 v1.5
    `decrypt` strips at the first `0x00` **without checking the mandatory `00 02`
    prefix**, so it accepted ~82% of *random* blocks (measured 2459/3000) and every
    earlier "login RSA decrypted" line was noise. `_rsa.py` now does a strict
    raw-RSA decode (`_strict_pkcs1v15`, guarded by `_rsa.py selftest`); a foreign block
    is rejected with no false positives. `server/re/_login_probe.py` is the standalone
    experiment.

  Consequence: a patched client needs **no harvester and no memory scan**.
  `_pserver.try_login_rsa` parses the JSON on every login and gets key, IV **and the
  SteamID** — the identity with which a multi-user session registry can key the
  request — and adopting the login block on each login also tracks the within-launch
  key rotation.
* **Frida-free key acquisition — SOLVED (2026-09-24).** The client serialises a
  small JSON while building the login request and keeps it readable in memory:
  `{…,"version":"<client version>","key":"<32 uppercase hex>","iv":"<16 uppercase
  hex>"}`. `server/re/_harvest_mem.py` scans the game's writable memory for
  `"key":"…","iv":"…"`, extracts key/IV and writes `server/session_key.json` —
  **no Frida, no RSA swap, no client modification, no official server**. Because
  `_pserver.py`'s `ensure_key()` holds login until `session_key.json` exists, the
  scan wins the race deterministically even though the JSON is **transient**
  (freed once login completes). The harvester therefore keeps the last key and
  clears it only when the game process exits, so a relaunch waits for the new
  session's key instead of serving the old one (a stale key gives the client the
  “Object reference not set…” NRE, indistinguishable from having no key).
  Verified end-to-end in-game (login → `c2s_get_gameinfo` → `c2s_get_myinfo`).
  This is now the **fallback for an unpatched client** (and for investigation
  tooling) rather than the deployment path: the in-process drop-in DLL above needs no
  scan. A *host-side* patch after launch cannot work — the client caches its
  `RSACryptoServiceProvider` from the baked key at `zf` static-init, before the patch
  lands (a full-scan patch of the literal, the managed string and the raw cached
  modulus left the login block encrypted to the original key). Either way
  `zf.aes_key`/`aes_iv` never appear on the HTTPS wire in the clear.
* Request bodies = b64( **magic `d3ad76d3adb8` (6 B)** ‖ AES-CBC-PKCS7(json) )
  *(supersedes the “fixed 16-byte prefix” reading — that was the magic plus the first
  ciphertext block, shared across requests only because those requests shared their
  first plaintext block)*. Responses are plain b64(AES-CBC-PKCS7(json)) — verified
  byte-for-byte by re-encrypting captured payloads.
* Decrypted endpoints: `c2s_login`, `c2s_get_myinfo`, `c2s_get_gameinfo` (the
  **1,201-entry music list**) and `c2s_get_pattern_file`.
  Music-list fields: `MUSIC_ID, TITLE, TEMPO, MIN_TEMPO, MAX_TEMPO, VERSION, LEVEL, NOTE,
  CRYPT_KEY, JUDGEMENT_TIME, GAUGE_RATE, DLC, GAME_MODE, RATING_CATEGORY, SUB_DLC, LINK_TYPE`.
* Offline decryptors: `tools/mitm/_decrypt_api.py`, `_decrypt_api_all.py`.

### 3.2 DTOs and keys

| DTO | Fields |
|---|---|
| `zf.wy` = `S2C_GET_PATTERN_FILE` | `final_url_ez`@0x10, `final_url_ezi`@0x18, **`bundleCryptKey`**@0x20, `result`@0x28 |
| `zf.wx` = `C2S_GET_PATTERN_FILE` | `appid`, `musicresourcename`, `keymode`, `levelmode`, `gamemode` |
| `zf.wz` = `C2S_GET_USERINFO` | `appid`, `steamId:UInt64[]` — the leaderboard profile fetch; 10 ids observed in one request |

**The DTO field sets are recoverable without decryption, from `global-metadata.dat`.**
Its string table contains plaintext field names grouped by class (classes are obfuscated,
fields are not), so `strings` over a window around a known field names the whole struct.
Mined 2026-09-24:

| DTO | Field set |
|---|---|
| `S2C_GET_USERINFO` | `memberinfo` (list), `result`; each **entry = `STEAM_ID`, `LEVEL`, `RATING` only** — *not* the full `c2s_get_myinfo` `memberinfo` struct. There is **no nickname field anywhere** in the client (`grep -a NICK global-metadata.dat` is empty) |
| `C2S_SET_GAME_CLEAR` | `appid`, `musicid`, `keymode`, `levelmode`, `lamp`, `gamemode`, `log_data` |
| `S2C_SET_GAME_CLEAR` | `level`, `exp`, `nextExp`, `result` — explains the 48-byte (64-char b64) response exactly |
| `S2C_GET_MYINFO` | `memberinfo`, `config`, `clearlist`, `course_clearlist`, `result`; `memberinfo` = `MEMBER_ID STATUS PLATE ACC_DATE REG_DATA ROUND LEVEL EXP NEXT_EXP RATING`; each `clearlist` entry = `MUSIC_ID` + `LAMP SCORE RATE COMBO KOOL_JUDGEMENT COOL_JUDGEMENT GOOD_JUDGEMENT MISS_JUDGEMENT FAIL_JUDGEMENT PLAY_COUNT` |
| `loungeloglist` | `appid`, `loungeloglist` (list), `result`; entry = `SEQ`, `MEMBER_ID`, `STEAM_ID`, `INQUIRY_CODE`, `MUSIC_ID`, `GAME_MODE`, `LOG_DATA` |

* **`clearlist` arrays are 16-wide and indexed keymode-major:** `idx = (keymode − 1) * 4
  + (levelmode − 1)` with `keymode` 1=4K, 2=5K, 3=6K (the API's 1-based key mode) and
  `levelmode` 1=EZ…4=SHD. Verified on the real `server/data/myinfo.json`: 156 of 184
  entries carry only index 3 (4K SHD), and multi-variant entries are natural pairs like
  `[3,7]` (4K+5K SHD) and `[3,6]` (4K SHD + 5K HD). This is the per-user progression
  model the multi-user store has to reproduce.

* **`bundleCryptKey` — SOLVED.** It is **not a key**: it is
  `base64( AES-256-CBC/PKCS7( 32-byte constant ) )` under the client's **own live session
  key and IV**, used as ASCII — the same cipher as the API bodies (§3.1). Decrypting a
  captured token with the session key yields the payload

  ```
  32-byte payload constant:
  d3163d646fedbbcc07a752f663fcd4cf06f5f9eedbadcc70244f20c82ad76922
  ```

  and re-encrypting that payload reproduces the served 64-char token **byte-for-byte**
  (verified against the token the official server had just served in the same session).
  It is a **build-time constant of the client**, not session material: two tokens captured
  under *different* session keys decrypt to the same 32 bytes. It is a **knowledge proof**
  — the server demonstrates it knows the session key by encrypting a fixed plaintext,
  which the client decrypts and compares with its own copy of the constant.
  *(Supersedes “96-character hex”, “per-song”, “session-scoped”, and the earlier “only
  thing acted on, role unknown”.)* It is **not** the chart key (§3.3).

  Memory evidence for the comparison, in the session whose key was `316A60CA…`: a
  full scan finds the constant **exactly once**, as a `byte[32]` (IL2CPP array header:
  `bounds = 0`, `length = 0x20` at `+0x18`) at `0x75e295c0`, with the live
  `zf.aes_key`/`aes_iv` strings in the same region. The *token* had two copies (both
  response-derived); the constant has one, because it is the client's own — which is
  also why scanning for the token never revealed its purpose.

  The two failure modes are why this hid for so long: a token that **cannot decrypt**
  (random bytes, or a token from another session's key) gives **8CN26 “Song Load
  timeout”**, which reads like a corruption verdict but is a *wait*; a token that decrypts
  but carries the **wrong payload** trips a *tamper kill* — "An unrecoverable error has
  occured. The program will now be terminated." (a message that sits right beside the
  8CN26 literal in the blob, which is how it was noticed as a distinct path).
* **`CRYPT_KEY`** — a per-song 16-element `{1,2,3}` sequence; a chart/note-obfuscation
  parameter, **not** cipher key material.
* **Naming is correct**: `final_url_ez` = the **chart**, `final_url_ezi` = the
  **keysound index** *(supersedes the earlier “inverted” claim)*.
* **The current chart's labels are readable at runtime, in memory.** `InGameCore`'s
  `patternFileInfo` is null by capture time, but the game holds the `c2s_get_pattern_file`
  **request JSON** as a UTF-16 string:
  `{"appid":"1477590","musicresourcename":"Rebind","keymode":"2","levelmode":"3","gamemode":"1"}`.
  So `musicresourcename` (the song name), `keymode` and `levelmode` can be read from the
  running game with no API capture — see `tools/il2cpp/_findstr.js` `patternjson`, which
  scans `rw-` ranges for the `{"appid":"` prefix (~2 s, one hit). `ripper/dump_song.py` uses it as
  the primary source and falls back to the chart name, then the API label cache.
* **`keymode` is 1-based over the key modes**: `1` → 4K, `2` → 5K, `3` → 6K (all three
  confirmed against the user's own labels). `4`+ is unobserved. It agrees with the key mode
  derived from the chart, which is a useful cross-check: a disagreement means the runtime
  state and the chart file are from different songs.
