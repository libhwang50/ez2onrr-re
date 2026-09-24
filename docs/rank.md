# 3.7 Rank server & score upload

> Part of the EZ2ON REBOOT:R technical report — index: [docs/README.md](README.md).

`game1-rank.ez2game.co.kr` serves plaintext `GET`s (`?data=…`); requests carry a
per-request base64 blob (a signature — semantics unverified). Responses are either empty
(200, `Content-Length: 0`) or a flat CSV.

| query | response |
|---|---|
| `get_battle_server_ip` | the battle-server address as plain text (`3.37.247.33:9902`) — raw TCP, bypasses the HTTP proxy entirely |
| `rating,<steamid>,<sig>` / `totalranking,<steamid>,<sig>` | empty; the in-game rating display survives an empty reply — because the displayed rating is **computed client-side and is per key mode** (a server serving one static myinfo `RATING` still shows distinct per-mode values, e.g. 4K ≠ 5K, that drift as you play; most likely derived from the `clearlist` best-rates × chart levels). The myinfo `RATING` field is not the displayed number |
| `plf…` | empty — **the score upload**; the whole record is in the URL |
| `get<rank_id><keymode><levelmode>,<page>[,<steamid>]` | leaderboard CSV of `rank,score,steamid` triplets |

`plf` fields observed for two Finite 5K HD plays (placeholders for the personal
parts): `plf<steamid>,<nickname>,27948,0,5,2,1,-1,<score>,<kool>,<cool>,<good>,
<miss>,<fail>,0,1,1,4,0,0,50,0,<acc×100>`. A second play of the same chart
changed **only** the score, the five judgement counts and the trailing accuracy
field — every other field was byte-identical. `27948` is the **rank-server's own song id** (the API's
`MUSIC_ID` for Finite is 9916 — two separate ID spaces; the leaderboard query uses the
same id, and its `23` suffix = keymode 2 / levelmode 3). The judgement counts sum to the
chart's total notes (`NOTE[6]` = 985 for Finite 5K HD — result screen, upload and music
list all agree), and the last field is accuracy ×100. The constant fields (`27948`,
`0,5,2,1,-1`, `0,1,1,4,0,0,50,0`) are mode/song constants across plays — `5` looks like
the key-mode's key count — but one mode pair is not enough to pin them.

**The client fetches the `.ezi` and `.ez` in either order**, and retries a failing
chart download **5 times** (3 s apart) before booting the song to the main screen.

**Where the rank traffic comes from**: the Lounge's **RANKING** tab (§3.5) is what
issues `get<rank_id><keymode><levelmode>,<page>` and the batched `c2s_get_userinfo` calls,
so opening it is the capture recipe for leaderboard/progression shapes.

**Leaderboard structure** (from a full official-server session): one query returns the
**whole Top100** (`get2794823,0` ≈ 2890 B ≈ 100 × 29 B of `rank,score,steamid`) — the
client pages it locally. **MyRange** = `get<rank_id><km><lm>,1,<steamid>` (~3105 B
covering the requester's own region) and is re-queried on every view. Each displayed
page of 10 players triggers one `c2s_get_userinfo` (response ≈ 832 B for 10 profiles ≈
80 B/profile — a compact profile list, fields still uncaptured). `set_game_clear`
response length **varies** (48 B after a new-record play, 64 B without). `rating` /
`totalranking` were empty in every captured session, and `plf` uploads happen for
non-record plays too.

**Chart-load failure 8CN26 = "Song Load timeout" — one flag, one coroutine.**
The popup text ("게임 파일이 손상되었습니다 … ErrCode: 8CN26") is the generic wrapper
the crash reporter shows; the code itself is the game's message table, where the
code and its text are stored concatenated:

```
8CN26Song Load timeout1YDMD : m:K14JVmLV Error : id:{0} m:{1}
An unrecoverable error has occurred.
The program will now be terminated.
```

The raise site is a single instruction in the song-load coroutine, reached
through that literal's accessor:

```
0x6ffff2fa7327  call  <accessor for "8CN26">        ; in ft.MoveNext @ 0x6ffff2f74230
0x6ffff2fa736f  call  InGameCore.dci(this, str166, str167, "8CN26")   ; the reporter
```

`ft.MoveNext` fetches two strings via `oj.UI(166)` / `oj.UI(167)`, fetches the
`"8CN26"` literal, and calls the reporter — then returns `false`. **`dci` is also
the only writer of the latch the coroutine checks**, so the flag means "an error
was already reported" and the popup shows the last report:

```
0x6ffff2e87fb5  mov byte ptr [rbx + 0x798], 1       ; inside InGameCore.dci
0x6ffff2fa7205  movzx eax, byte ptr [rax + 0x798]   ; inside ft.MoveNext
0x6ffff2fa721f  jne  -> report 8CN26, return false
```

There is no earlier hidden error: the **wait inside `ft.MoveNext` itself is the
cause**, and what that wait depends on is the one open item (§7.8). Earlier
readings of 8CN26 as an integrity verdict were wrong (the client has, at the
popup, already **downloaded, decrypted and parsed everything** — 5 lanes with
notes, `instrumentDic` = the served `.ezi` line count — so the failure is
post-parse, and "the game file is corrupted" is not what the code says).

**What the client actually checks in the pattern response: only the bCK.** With a
*passing* baseline (hybrid: forwarded login + forwarded pattern) the
`server/re/_exp.py` knobs isolate it:

| run | knob | result |
|---|---|---|
| A | none | loads |
| B | `bck garbage` (48 random bytes, same base64 shape) | **8CN26** |
| C | `urls skew` (`Expires` +1 s, so the CloudFront signature no longer matches) | **loads and plays** |
| D/E | `urls future` / `expire` | fail, but only because the bCK was untouched — C proves the URL is never validated |

So the CloudFront URL signature and its expiry are **never** verified (our own
minted `Expires` with a stale signature loads fine), and `bundleCryptKey` is the
only element acted on. A private login cannot make the upstream mint URLs — it
returns `{"result":0}` (24 B) and the client retries until `GPF 5 TIMES FAILED` —
which is why hybrid mode must forward the **login** too, not just the pattern.

**Fully offline chart loads: WORKING, with nothing borrowed — confirmed in game.**
Private login (`endpoints = ''`, no passthrough), our own minted `Expires`, CDN files from
the local cache, and a token the server **mints itself** from the session key it reads live
(§3.2): Finite 5K HD loads and plays. **This is now the server's default** — the old
`hybrid off` + `urls now` + `bck mint` setup step is built in, the 32-byte payload
constant is embedded in `_pserver.py` (`DEFAULT_BCK_PAYLOAD`), and a knob of
`off`/`none` is what turns a piece of the default off for an experiment. Chart serving
stays **exact** by default (`chart any` serves a different variant's note assignment, so
it is opt-in only).
Protocol-level proof: our minted token is byte-identical to the one the official server
had just served in the same session, so the client has already accepted our own output in
game. Recipe: `server/README.md`.

**Why it hid, and what the token is actually for.** Each observation pointed away from
the truth on its own:

* a full-heap scan (3.4 GB, budget not exhausted) finds **exactly two** copies of the
  *token*, both derived from the response — because the client never stores the transit
  value, it stores the *constant*;
* a failing load opens exactly **one** connection (the handshake-only TLS probe to
  `3.37.247.33:443`; no 4649 frame, no 9902) — because the comparison is local;
* no hash/HMAC/AES sweep over the session key, the Steam ticket, the login ciphertext or
  the SteamID finds the payload — because it is a compile-time constant, not a derivation;
* garbage bytes give a *timeout* while a wrong payload gives a *tamper kill* — different
  stages (decrypt vs compare) produce different symptoms.

Residual curiosity, not a blocker: the constant's *preimage* is unknown. It is a value of
a particular client build, so a future game update can change it; re-derive it by
decrypting any captured token with that session's key — which is exactly what
`_pserver.py`'s `bck_payload()` does when `server/data/bck_payload.hex` is missing.

**How literals are addressed in this build (needed for any future hunt).**

* Each assembly's literal blob lives in one anonymous mapping that also holds the
  static-fields region; its base is stored as a *static field of `System.String`*:
  `blob = [ [StringKlass+0xb8] + STATIC_OFF ]` — sampled `STATIC_OFF` values
  `0x8320` and `0x9f858` (`deref <global> 0xb8,0x8320`).
* Per-literal accessors are `<PrivateImplementationDetails>{…}.a.XX` methods that
  set `ecx` = literal index, `edx` = offset in the blob, `r8d` = length and call
  the assembly's helper (`…2fd2390`, `…27b5be0`). There is **no** `mov edx,<off>`
  against a mapping base and **no** RIP-relative `lea` to the blob — the offset is
  relative to that runtime base, which is why every mapping-base scan returned 0.
* A second, index-only resolver exists: `oj.UI(index)` returns a string for an
  index in a different table (the error paths use it).
* The `dc*` cluster holds the chart decryptor (`dcf`/`dcg`, §3.3), the reporter
  (`dci`) and `dch`.

**Scanning caveats that cost time here (see `tools/README.md`).**

* A byte-by-byte JS loop must only ever walk the module's **own** `r-x` ranges:
  the earlier `base >= mod.base && base < base+mod.size` filter also matched
  Wine/Unity JIT mappings, so loops walked ~6 GB and looked like hangs, while
  native `scanSync` (~1 GB/s) merely took seconds.
* `findhex`'s original 2 GB budget scanned `rw-` before the code and silently
  returned `hits=0` for code/pointer searches. It now defaults to 16 GB, scans
  `r-x` first, and reports `budgetExhausted`.
* AOT code is decrypted per method: scan after the path has executed.
* Any single long RPC can wedge the Gadget if abandoned — scans are chunked
  (`scanCallersChunk`) so Ctrl-C is safe between chunks.

**Operating modes.** (1) *Hybrid* — official login + pattern passthrough, our CDN
cache, private scores. (2) *Offline* — **the default**: nothing is forwarded, the
CDN URLs and the `bundleCryptKey` token are both minted server-side from the
live session key (the token's 32-byte payload constant is embedded in
`_pserver.py`), and a chart captured for the requested keymode/difficulty is
served. The only
input still taken from the running game is its session key (`re/_harvest_session.py`).

**Private-server trap:** an unhandled exception inside a mitmproxy addon hook does *not*
abort the request — mitmproxy logs it and **forwards the request to the real upstream**.
The first `server/_pserver.py` test therefore mixed real and private responses
invisibly. The addon now catches everything and serves explicit errors instead — keep
that guarantee when editing it (a request to a game host must never leak upstream).
