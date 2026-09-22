# EZ2ON REBOOT: R — Reverse Engineering Technical Report

Current state as of 2026-09-22. `README.md` is the user-facing guide; `tools/README.md`
covers the investigation harness; `server/README.md` covers the private server. Superseded
conclusions are marked *(supersedes …)* rather than kept as narrative.

## 1. Environment

| | |
|---|---|
| Game | EZ2ON REBOOT: R — Unity 6000.0.78f1, IL2CPP, x86-64 Windows build |
| Runtime | Proton / Wine (Steam Linux Runtime `pressure-vessel`) |
| Core modules | `EZ2ON.exe`, `GameAssembly.dll`, `EZ2ON_Data/il2cpp_data/Metadata/global-metadata.dat` |
| Assets | `EZ2ON_Data/StreamingAssets/Packs/01/` (audio), `02/` (video) — ~1,231 AssetBundles |
| Instrumentation | Frida Gadget on `127.0.0.1:27042`, attach target `"Gadget"`; `.venv/bin/python` (frida, capstone, pefile, pycryptodome) |
| Anti-cheat | None mapped natively. `uncheatercsd.dll` exists as a managed IL2CPP assembly; nothing blocks this work. |

The game defines a global `Module`/`GameAssembly` that **shadows Frida's** — always
use `Process.getModuleByName`.

### Ground rules (learned the hard way)

* **Read-only, always.** `Interceptor.attach` has crashed the game on every attempt —
  hot BCL functions and cold, once-per-launch cipher constructors alike.
  `MemoryAccessMonitor` guard pages crash it too (`da`'s static-fields page is read
  ~350×/s from several threads and the guard is one-shot).
* Use **managed invocation** via `frida-il2cpp-bridge`, plus **≤4 Hz host-side polling**.
  Attach the `gum-js-loop` thread to the domain as little as possible, and never **hold**
  managed objects across invocations: `Il2Cpp.perform` attaches Frida's own thread as a side
  effect, and the bridge keeps the enumerator/boxed values it returns as raw pointers the
  IL2CPP GC does not know about, so a GC mid-loop frees them and the next invoke touches
  freed memory.  Walking `Dictionary`-shaped state with
  `get_Keys`/`GetEnumerator`/`MoveNext`/`get_Current` is the worst case — read the backing
  array instead, or derive the data host-side.
* **`onMain()` is only for OS crypto.** `onMain()` gets onto the game's main thread by
  hijacking it with `Process.runOnThread`, and under Proton that has **livelocked** it: the
  thread spins at 100% CPU, the gadget's message loop wedges so the RPC never returns, and
  the game is left frozen with no way to attach again.  The earlier reading — that the
  managed *invocations* were the hazard — was wrong: the hang was caught inside `daRusFull()`,
  which invokes nothing.  Reads use plain `Il2Cpp.perform`; only a call into the OS crypto
  provider (Wine/CNG thread affinity) needs the main thread.
* **Bound every RPC.** A hijack that livelocks never returns, so a plain synchronous call
  blocks on a futex forever with no output.  `dump_song.py` runs each call on a daemon thread
  and treats a timeout as a wedge.
* When the read path dies it does **not** raise a clean error: the game's main thread can
  exit while the process lingers (window frozen on its last frame, Steam still listing it as
  running, ~128 worker threads alive, `/proc/<pid>/maps` empty only because `/proc/<tgid>/*`
  reads the dead leader's `mm`), or the Frida script is unloaded. Reads then fail with
  `failed to run on thread`, `couldn't collect attached threads`, or `script has been
  destroyed`. None recover — detect and stop, do not keep polling.
* Rebuild symbol maps **every session** — the module base changes per launch.
* Treat AOT code as **lazily decrypted per method** — scans miss methods that have not
  yet run in that process.

The full list of crash-causing scripts lives in `tools/README.md`.

## 2. AssetBundles — SOLVED

* Every bundle's **first 1,024 bytes (0x400)** are XOR-encrypted with a static keystream;
  **offset 0x400+ is plaintext** LZ4/LZMA Unity data.
* Master key `true_key_1024.bin` =
  `RAM_decrypted_header[0:1024] XOR disk_header[0:1024]`, harvested zero-hook with
  `harvest_key.py`.
* With that key every bundle decrypts to a valid `UnityFS` container
  (`decrypt_all.py`, `find_bundle.py`).
* **Audio / BGA extraction** (`extract_assets.py`) parses raw C++ object bytes directly —
  AssetRipper's UTF-8 path corrupts binary `.bytes`. `TextAsset` → FLAC/OGG keysounds;
  `VideoClip.m_ExternalResources` → 720p H.264 `.mp4`.

## 3. Chart delivery

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
* **The client generates both itself, per launch** *(supersedes "overwritten at login" as
  the mechanism)*: `zf.gnf()` draws 32/16 bytes from `RNGCryptoServiceProvider` and
  hex-encodes them (`BitConverter.ToString` → strip `-`; uppercase). Pre-generation
  defaults are the metadata placeholders `01234567890123456789012345678901` /
  `0123456789012345`. Read the live values with `il2cpp_field_static_get_value`, never
  the metadata defaults.
* **The key never crosses HTTPS.** `c2s_login` carries no key material: the encrypted
  `data=` part is `RSA-2048/PKCS1v1.5("")` — an *empty* plaintext, `zf.publicKey` being
  the baked-in server key (`<RSAKeyValue>` literal; `zf` = `WebManager`) — followed by
  plaintext form fields `ticket=<Steam auth session ticket, hex>` and
  `identity=<SteamID or a constant>`. The real server must learn the AES key
  out-of-band (presumably the raw-TCP control/battle channels, `zf` RSA+AES); a private
  server reads it from the running game instead (`server/_harvest_session.py`).
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
| `zf.wz` = `C2S_GET_USERINFO` | `appid`, `steamId:UInt64[]` — the leaderboard profile fetch; 10 ids observed in one request. The client **crashes with a JSON parse error** (popup → exit) when the response is a single-`memberinfo` object, so `S2C_GET_USERINFO` almost certainly carries a **list** of profiles (shape still uncaptured) |

* **`bundleCryptKey`** — a **64-char base64 string decoding to 48 raw bytes** *(supersedes
  the “96-character hex” reading; `da.rus.rjn` is its base64-decode, not `bytes.fromhex`*,
  same 48 bytes). **Session-scoped**: byte-identical for both
  songs sampled in one session, so the earlier “per-song” reading is superseded — which
  also retracts the note that had superseded the original per-session claim. It is **not**
  the chart key (§3.3).
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
  scans `rw-` ranges for the `{"appid":"` prefix (~2 s, one hit). `dump_song.py` uses it as
  the primary source and falls back to the chart name, then the API label cache.
* **`keymode` is 1-based over the key modes**: `1` → 4K, `2` → 5K, `3` → 6K (all three
  confirmed against the user's own labels). `4`+ is unobserved. It agrees with the key mode
  derived from the chart, which is a useful cross-check: a disagreement means the runtime
  state and the chart file are from different songs.

### 3.3 CDN payload cipher — SOLVED

**The cipher is `mask ∘ AES-256-CBC/PKCS7`, with the key and IV baked into the binary.**
Decryptor: `decrypt_chart.py` (repo root).

```
plaintext = AES_256_CBC_decrypt( unmask(ciphertext), key=<svk|svm|svo>, iv=<svl|svn|svp> )
```

**Stage 1 — `unmask`.** A data-independent, one-pass XOR mask, exactly 64 rounds per
byte. It depends only on the byte index `ebx`, never on the key or the data, so it is a
fixed keystream. Tables are the statics `InGameCore.svq` (64 B) and `InGameCore.svr`
(16 B): `S[i] = svr[svq[i] & 0xf] ^ svq[i]`, and for each `ebx`

```
r_i = (ebx * i) % 255 ;  if r_i % 10 == 0: r_i = 12      # the `cmove` at 0xac729b
mask(ebx) = XOR over i in 0..63 of ( S[i] ^ r_i ^ (ebx & 0xff) )
```

**Stage 2 — AES-256-CBC/PKCS7**, key and IV from one of **three static pairs**, all in
`InGameCore`:

| pair | observed on |
|---|---|
| `svk`/`svl` | Engine 4K SHD, Finite 5K HD |
| `svm`/`svn` | Change My World 4K SHD, Hyper Magic 4K SHD |
| `svo`/`svp` | Conflict 4K SHD, Rebind 4K SHD |

**The pair is selected per payload by validation, not recorded anywhere.** The game does
not store a key index; `bundleCryptKey` is identical across songs that use different pairs,
and the CDN path bucket differs even between a song's own `.ez` and `.ezi` while the pair
does not — so neither is the selector. For any given payload exactly one pair yields valid
PKCS7 padding, so `decrypt_chart.decrypt()` tries all three and accepts the one whose
plaintext has valid padding **and** looks like a chart (`EZFF`) or an index (printable
`[index] [velocity] [filename]` lines). `decrypt_named()` also returns which pair matched.
Both stages work **in place** on the whole buffer.

**Where it lives.** `InGameCore.dcf` (RVA `0xac71b0`) is the entry point: it runs the
64-round mask and then **tail-`jmp`s** into `InGameCore.dcg` (RVA `0xac7380`), which
configures `AesCryptoServiceProvider` — `set_BlockSize(0x80)`, `set_KeySize(0x100)`,
`set_Key`, `set_IV`, `set_Mode(CBC=1)`, `set_Padding(PKCS7=2)`, `CreateDecryptor()`.
Callers: the `ft.MoveNext` coroutine and `ff.cuc`.

**Verification (end-to-end).** `cur_conflict_ez_url.ez` → `EZFF` magic, name `4-shd`,
BPM `160.0`, 64 tracks, 64 `EZTR` blocks, valid PKCS7. `cur_conflict_ezi_url.ezi` →
2719 plaintext keysound lines whose `index → filename` mapping matches the game's own
parsed `instrumentDic` **2719/2719**. Engine (`svk`/`svl`) → `EZFF` v7, BPM `174.0`,
64 tracks, 865 keysounds matching an `instrumentDic` count of 865. Four payloads across
three songs, two key pairs, all four decoded correctly.

#### Corrections to earlier conclusions

| Earlier claim | Reality |
|---|---|
| "per-song key" (`bundleCryptKey` / `da.rus.rjn`) | **No.** The chart key/IV are the **static** `svo`/`svp`. `rjn` is a transport/audit record (§4.2) and is not the chart key. |
| "static analysis cannot find the decryptor; no construction site" | The site is `dcf → dcg`, reachable by scanning for **direct `E8` calls** to the `dc*` cluster. The earlier scan only looked for `RijndaelManaged`/`Aes.Create` ctors, and `dcg` instantiates `AesCryptoServiceProvider` — a site that *was* found but misread. |
| "`dcg` is inert — sets `BlockSize=256`, CNG rejects it" | **Two errors.** The `0x100` goes to `set_KeySize` (AES-256), not `set_BlockSize` (`0x80` = 128). `dcg` is fully live. Slots are resolved via `SymmetricAlgorithm`'s vtable: `0x238`=`set_KeySize`, `0x1a8`=`set_BlockSize`, `0x1f8`=`set_Key`, `0x1d8`=`set_IV`, `0x258`=`set_Mode`, `0x278`=`set_Padding`. |
| "`svk`–`svr` are dismissed, not key material" | **They are the cipher.** `svq`/`svr` are the mask tables; `svk`/`svl`, `svm`/`svn` and `svo`/`svp` are three alternative chart key/IV pairs. |
| "16-byte constant header" — `ct₁ ⊕ ct₂` is zero for bytes 0–15 | **Not reproducible.** Conflict and Rebind use the *same* key pair yet differ from byte 0. The earlier observation must have compared two charts sharing both key and a plaintext preamble. |

**Why the ~2.7 M-key sweep failed:** it searched the wrong key space (`rjn`/`bundleCryptKey`
derivations) and, crucially, tested AES directly against the ciphertext — without the
stage-1 mask, no key can ever produce `EZFF`.

**Resolution of an earlier open item:** the sibling statics `svk`/`svl` and `svm`/`svn`
are **not** guarding a different payload type (as §3.3 previously speculated) — they are
alternative chart keys. Its corollary is that a decryptor which hardcodes one pair will
silently produce garbage for a chart that uses another, so always validate.

**Still open:** which songs map to which pair is not understood — the choice looks like a
build-time/authoring decision rather than anything in the payload. `svm`/`svn` has not
been observed at all yet.

### 3.4 MITM oracle — `tools/mitm/_cdn_rewrite.py`

A mitmdump addon that captures every `ez2game.co.kr` body under `mitm_live/` and can
rewrite CDN bodies on the fly via `_rewrite.json` (`op`: `none`/`zero16`/`zero32`/
`trunc16`/`trunc32`/`zeros`, plus `offset` and URL `match`). The config is re-read per
response, so experiments need no restart.

> If a rewrite hangs the loader, set `{"op":"none"}` and retry — nothing persists.

### 3.5 EZ2AC format lineage

* **`.ez` = note chart**: magic `EZFF`, version byte at `0x05` (observed `0x08`), `0x06–0x45`
  internal name (NUL-terminated), `0x86` ticks/measure (observed `0xC0`), **`0x88` initial
  BPM (float)**, `0x8C` track count (u16), `0x8E` total ticks (u32), `0x92` other BPM
  (float); `EZTR` per-track blocks follow, `count == track count`.
  Reference sample — Conflict: `4-shd`, BPM 160.0, 64 tracks, 19,680 ticks, 64 `EZTR`.
* **`.ezi` = keysound index, and it is TEXT**: `[index] [velocity] [filename]` per line,
  `\r\n` terminated, velocity 0/1, PKCS7-padded at EOF. Corroboration — MilK: 18,192 B ÷
  807 keysounds = **22.5 B per line**; Conflict: 2,719 lines, mapping verified against the
  game's parsed `instrumentDic` 2719/2719.
* **The `.ezi` is per song, NOT per mode or difficulty.** Comparing every variant captured
  (Conflict at keymode 1/levelmode 4, 1/3 and 3/3; Engine at 1/4, 3/3 and two gamemodes;
  Destr0yer at 1/4 and 3/3; PUPA 5K HD vs 5K NM; **Hyper Magic 4K SHD vs 8K EZ**) each
  song's decrypted `.ezi` is **byte-identical** — one sha256 per song, even across key
  modes. So the keysound bank is a property of the song, and no new difficulty or key mode
  ever needs a fresh keysound set.
* **The `.ez` chart differs by keymode and difficulty — but only in how notes are ASSIGNED,
  not in what sounds.** Comparing the multiset of `(position, keysound)` over *all* tracks:
  * Conflict **4K EZ ⊂ 4K SHD** — 6386 events, none unique to EZ; SHD has 7 extra;
  * Conflict 4K HD is likewise a strict **subset** of 4K SHD (7 dropped, 0 added);
  * PUPA 5K HD vs 5K NM — **identical**, 4047 events each, and the two render to
    **byte-identical audio**;
  * Hyper Magic 4K SHD vs 8K EZ differ by 3 events out of 2506.

  Meanwhile the lane counts move enormously — Conflict's lanes hold 330 notes on EZ, 1304
  on HD and 1814 on SHD, while the total stays ~6390. So difficulty moves notes between the
  player's lanes and the auto-played tracks; the *song* is essentially unchanged.
  **Practical consequence: one chart per song is enough to render the full song.**
* **The Lounge is a chart-harvesting route.** The in-game Lounge (watch a BGA with the song
  playing) goes through the same `c2s_get_pattern_file` flow and serves the song's **4K EZ**
  chart — confirmed by capture: the Lounge chart for Conflict was `4-ez` with an `.ezi`
  byte-identical to Conflict's. So charts can be collected by browsing BGAs, with no
  gameplay, and per the point above those 4K EZ charts suffice to render each song.
* **The `.ez` per-track counts differ by keymode and difficulty** (Conflict SHD vs HD differs
  in the lanes *and* in nearly every track 23–63, while the track-22 `MR` note is the same).
  It is the track *assignment* that moves, per the point above.
* **Key mode is directly readable from the chart**: the number of playable lanes is the
  count of tracks from 3 upwards that carry notes — 4 → 4K (API keymode `1`), 5 → 5K,
  6 → 6K (API keymode `3`), 8 → 8K. Confirmed on all four. 7K is unobserved (it is said to
  be course-only, behind the O2Jam Collaboration DLC).
* **Difficulty is `levelmode`: 1=EZ, 2=NM, 3=HD, 4=SHD** (Conflict and Engine at levelmode 4
  are both SHD; Conflict levelmode 3 is HD). `gamemode` 1 and 2 produced identical charts
  for the same mode/difficulty, so it is not a chart selector.
* **The CDN URL hash is not a content hash.** A song's `.ezi` URL differs per variant while
  the decrypted bytes are identical, so the path segment cannot be used to identify
  content — match on the decrypted payload instead.
* **Positions are ticks; the game works in measures.** `InGameCore` divides by
  `ticksPerMeasure` (Conflict: 192), so `normalNoteData[*].seu` is measures and
  `<set>k__BackingField` is seconds (`seu × 60/BPM × 4`). Cross-check: the first 1P Key1
  note is tick 384 = measure 2.0 = keysound 166, matching the game's `{seu: 2.0, sev: 166}`.
* **Note record = 13 bytes** (the v7 sizing) for both v7 and v8: `pos`(u32), `type`(u8),
  then 8 param bytes. Type 1 uses `keysound`(u16), `velocity`(u8, 127 in practice),
  `pan`(u8, 64 = centre), pad, a 2-byte field at `params[5:7]`, pad. Types 2/3/4 are
  volume (u8), BPM (float), beats-per-measure (u8).
* **The v8 anti-tamper step does NOT apply to CDN-served charts.** `ezunfn` (subtract
  `0xF9` at `0x1F8`/`0x400`/`0x5F0` every `0x600`) is documented for arcade v8 files, but
  running it on a decrypted REBOOT payload *introduces* 38 non-monotonic positions, 67
  out-of-range positions and 4 invalid keysound indices, whereas the file as served has
  **zero** of each. Adding `0xF9` turns valid note types (`0x01`) into `0xFA`. Do not apply it.
* **Track index → lane, and long notes — SOLVED for 4K.** Verified against the game's own
  `normalLanes` over 3 songs x 4 lanes, 12/12 exact:
  * **tracks 3–6 are the 4K lanes, in order** (track 3 → lane 0 … track 6 → lane 3);
  * a type-1 note is a **long note iff `flags not in (0, 6)`**; `flags` is the uint16 at
    `params[5:7]`. Normal + long per lane reproduced `normalLanes` exactly.
  **`flags` is the hold length in ticks.** Confirmed against the charts: with that unit every
  hold ends at or before the next note in its own lane (43/43 in Changa 2, 83/83 in Rebind),
  whereas at twice that unit most holds would overlap the next note in the same lane, which a
  lane cannot do. Values are multiples of 12 ticks (a 1/16-measure grid), giving holds of
  0.2-2.6 s, and `bar`/`hold` land on plausible musical positions. It has **no audio effect**:
  verified in-game that a long note's keysound plays exactly like a normal note's and is not
  sustained. So it drives judgement and the visual hold bar, and `visualize_song.py` uses it to
  keep a lane lit for the whole hold.
* **A late key press starts the keysound from the middle, not from its start** (reported
  in-game: missing the first tick of a long note and pressing after it). So the game plays the
  sample from an offset derived from ticks-elapsed-since-the-note-position. A renderer that
  always restarts each keysound at 0 therefore matches a *correct* keypress, not a late one —
  worth remembering when comparing a render against a sloppy play-through.
* **`name` at `0x06` is the chart variant, not the song name**: it is `<keys>-<difficulty>`, e.g.
  `4-shd`, `8-ez`, `5-nm`, `5-hd`. So it decodes the key mode **and** difficulty straight
  from the chart, which is more direct than asking the API. It is not always set — Engine
  and Revelation leave it empty — and `#PTMAKE` marks a chart built with the in-game
  pattern maker. Different songs genuinely share a tag: Conflict and Hyper Magic both
  carry `4-shd` because both are 4K SHD.
* **Key mode from the lane count**, which matches the name tag on every sample: 4 lanes →
  4K, 5 → 5K, 6 → 6K, 8 → 8K. (7K is unobserved; it is said to be course-only.) This is
  the fallback when the name is empty or `#PTMAKE`.
* **Track 22 triggers a supplementary `MR` layer, not the full song.** Every one of the 5
  captured songs holds a single type-1 note there (positions 0, 96 or 192 ticks).
  **Do not mistake it for the song** — per listening, it contains only the instruments too
  long or too incidental to sample as keysounds. Rebind's `MR` is ambience alone. Its
  filename varies (`00-MR.wav`, `MR.wav`, `99-BG.wav`, and for `ae_illusion`
  `mrt22Fix.wav` = "MR, track 22, fixed"), so resolve it from the chart:
  `parse_chart.py --backing --ezi f.ezi f.ez`.
* **The song is a render of the chart.** Playing every type-1 note on every track, each
  keysound at its scheduled time, reconstructs it. Tracks 3–6 are the player's lane input
  and 23–63 are auto-played instrument layers; the split does not matter for rendering —
  all of them sound. **Verified by ear against gameplay — reported as an exact match.**
* **Player vs auto is exactly `tracks 3 .. 3+lane_count-1`.** On all 12 captured charts the
  tracks carrying keysounds from 3 upward are that contiguous run and nothing else: 3–6 for
  4K, 3–8 for 6K, 3–10 for 8K. Everything from track 22 (the MR layer) and 23+ is
  auto-played. So `Chart.lane_count` is the rule, and a fixed `range(3, 22)` is only safe
  because no chart yet places a note in the unused 7–21 gap. `visualize_song.py` uses it to
  dim the auto rows (see §5).
* **One note triggers exactly one keysound.** The 13-byte record has room for a single u16
  index at `params[0:2]`; a byte census over all 32,923 type-1 notes shows `params[4]`
  non-zero exactly once and `params[7]` never, so there is no hidden second index. The pan
  byte (`params[3]`) confirms it: the rare same-keysound-at-the-same-tick cases (hypermagic
  1, kamui 2) are two *independent* notes with different `pan` that share a sample, not one
  note emitting two sounds. A per-keysound row therefore maps 1:1 to a note.
* **Nearly — but not quite — every declared keysound is played.** `declared-but-unplayed` is
  0 for conflict/rebind/suddendeath, but is **72 for ultimatum**, 3 for destr0yer and 1 each
  for changemyworld and hypermagic. Two charts also have a *used-but-undeclared* index, always
  a **track-22 placeholder** (index `0` in changa2, `255` in kamui) — the `MR` track pointing
  at an empty slot. These render as `(unknown)` rows.

### 3.6 Tick → seconds (validated)

```
seconds = ticks * 1.25 / BPM          # piecewise, at each BPM change
```

A measure is **always 4 beats of 48 ticks**, and `ticksPerMeasure` is always 192. So a
measure lasts `4 * 60 / BPM` seconds and one tick `60 / (BPM * 48)`.

**`beatsPerMeasure` (type 4/5 events) does NOT change timing** — it is visual/metrical only.
This matters: Conflict has a 4→7 change at tick 11136 and back to 4 at 14832, which makes
the difference between 175.41 s and 153.75 s.

| song | model | BGA video |
|---|---|---|
| Rebind | 162.58 s | 162.67 s |
| Conflict | 153.75 s | 154.47 s |

Both videos run slightly longer than the chart, consistent with a lead-out. Treating the
time-signature change as a real tempo change would be off by 21 s on Conflict.

`Chart.seconds_at(tick)` and `Chart.note_seconds()` in `parse_chart.py` implement this, and
`render_song.py` uses it to mix every note's keysound into an audio file, and
`visualize_song.py` draws that mix as a video with the keysounds overlaid on the BGA. All 5 captured
songs render; Conflict (6393 events, 2719 distinct keysounds) takes ~3 s and comes out
with a normal mix profile (mean ≈ −17 dB, normalised peak). Rendering is fast enough to do
in bulk — 5 songs in 11 s (`render_song.py --all`).
* **Open: note types 5/6/9** (and 8 in some files) are undocumented; the reference
  `ezinfo` reports them as unhandled. Exposed raw by `parse_chart.py`.

### 3.7 Rank server & score upload — partially decoded

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

**Leaderboard structure** (from a full official-server session): one query returns the
**whole Top100** (`get2794823,0` ≈ 2890 B ≈ 100 × 29 B of `rank,score,steamid`) — the
client pages it locally. **MyRange** = `get<rank_id><km><lm>,1,<steamid>` (~3105 B
covering the requester's own region) and is re-queried on every view. Each displayed
page of 10 players triggers one `c2s_get_userinfo` (response ≈ 832 B for 10 profiles ≈
80 B/profile — a compact profile list, fields still uncaptured). `set_game_clear`
response length **varies** (48 B after a new-record play, 64 B without). `rating` /
`totalranking` were empty in every captured session, and `plf` uploads happen for
non-record plays too.

**Chart-load failure 8CN26 — the files are NOT the problem.** A private-server
chart load that fails with "게임 파일이 손상되었습니다 … ErrCode: 8CN26" has, at the
error popup, already **downloaded, decrypted and parsed everything**: live-state
reads showed 5 lanes with notes populated, `instrumentDic` = 1131 = exactly the
served `.ezi` line count, and `da.rus` holding the exact ciphertext sizes. The
verdict is a **post-parse, session-dependent check**. Ruled out by experiment:
the URL shape (fresh Expires + well-formed 344-char signature still fails) and
the control channel *audit being skippable when blackholed* (`battle_server.txt`
→ `127.0.0.1:1` produced zero connections to the real server and the same
error). The remaining difference vs a working load: a genuine server session
over the **control channel (TCP 4649)** — where `da.rus` (ciphertexts + key) is
relayed and/or keysound audio flows. The in-game error popup embeds a
Bugsnag-style reporter (`event.applecrashreport`, `event.view_hierarchy`) and
its full text (Unity TMP rich text, `<size=28>로딩 실패</size>`) is capturable
from memory but memory scanning proved non-deterministically crash-prone.

**Chart-load failure 8CN26 — SOLVED: the pattern response must be FRESH.** A
private-server chart load that fails with "게임 파일이 손상되었습니다 … ErrCode: 8CN26"
has, at the error popup, already **downloaded, decrypted and parsed everything**
(live-state reads: 5 lanes, notes populated, `instrumentDic` = 1131 = exactly the
served `.ezi` line count, `da.rus` holding the exact ciphertext sizes). Isolation
experiments:

* official login + private (synthesized) pattern + private files → 8CN26
* private login + private pattern with **fresh-shaped** URLs (150 s expiry, 344-char
  signature) + private files → 8CN26
* private login + **replayed verbatim** official response (real signed URLs, real
  per-session `bundleCryptKey` — hours stale) → 8CN26
* official login + **PASSTHROUGH** pattern request to the upstream (fresh response)
  + private files → **LOADS AND PLAYS**

So the client validates the freshness/validity of the pattern response's signed URLs
(and/or the per-session `bundleCryptKey`, which differs every session), and rejects
stale or forged ones post-parse. The chart FILES are byte-identical across sessions
(sha256 `132bb600…` matches the CDN's own `x-amz-meta-sha256`), and the control
channel (TCP 4649) is **just a websocket-sharp Notice channel**
(`GET /Notice?id=<steamid>&name=<nick>&version=…`) carrying pings and announcement
banners — no session audit, no audio, no battle traffic during a full play session.

**Where the 8CN26 check sits (refined).** Mutating a *replayed* response's URLs
to a far-future `Expires` still fails, and the client **downloads both CDN files
successfully from the local cache first** (32160 + 32992 B, 200) — so the check
is neither a pre-download URL rejection nor a download failure. It is post-parse,
against the response content. The two surviving candidates are the CloudFront URL
signature and `bundleCryptKey`; isolating them needs a *passing* baseline, i.e. a
forwarded pattern response, which in turn requires a forwarded **login** (a
private login cannot make the upstream mint URLs — it answers `{"result":0}`,
24 B, and the client retries until `GPF 5 TIMES FAILED`).

**Operating modes.** Hybrid (works today): official login mints fresh pattern
responses (addon passthrough), CDN files come from the local cache, scores/records
stay on the private server. Fully offline: blocked only by the client's
freshness/signature validation of the pattern URLs — the error-site hunt
(`EZ2_HUNT=1`, literal-thunk → caller attribution) reads the exact check; if it is a
CloudFront signature verification with an embedded public key, patching that key
enables self-minted URLs.

**Private-server trap:** an unhandled exception inside a mitmproxy addon hook does *not*
abort the request — mitmproxy logs it and **forwards the request to the real upstream**.
The first `server/_pserver.py` test therefore mixed real and private responses
invisibly. The addon now catches everything and serves explicit errors instead — keep
that guarantee when editing it (a request to a game host must never leak upstream).

## 4. Runtime internals

### 4.1 Managed invocation

`tools/il2cpp/_il2cpp_bridge.js` is a vendored `frida-il2cpp-bridge@0.14.0`. Concat it
with a driver defining `rpc.exports.*`, then run via `sc.exports_sync.<fn>()`:

```js
function onMain(fn) {
  return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn()));
}
```

* Any method touching the OS crypto provider **SIGSEGVs from Frida's thread** under
  Proton — `onMain()` fixes it. (Wine/CNG limitation, not anti-cheat.)
* Helpers defined outside the callback are **not visible** inside
  `Il2Cpp.perform(() => {…})` — inline everything.
* `invokeRaw` uses the raw native pointer: a managed exception **aborts the process**.

### 4.2 `da.rus` — a transport/audit record, not the parse source

* Static `da.co` at **static offset 840 (0x348)**; fields `rjl`@0x10 (`.ez` ciphertext),
  `rjm`@0x18 (`.ezi` ciphertext), `rjn`@0x20 (the 48-byte transport key — **not** the chart
  cipher key; see §3.3).
* Built at the only `da.co..ctor` caller; `rjn` comes straight from
  `InGameCore.bundleCryptKey` (0x830).
* `da.co.fhj` `Array.Clear`s all three fields, then the caller sets `da.rus = null` — which
  is why no key or plaintext survives in memory.
* **Proven not to be the chart source**: substituting a marker-filled synthetic record
  does not affect song loading at all. *(supersedes the “`da.rus` holds the live pattern”
  reading — it exists so the key can be relayed and the buffers wiped.)*

### 4.3 Key offsets and constants

* `InGameCore` (instance): `normalNoteData` 0x510, `longNoteData` 0x520, `bpmNoteData`
  0x540, `instrumentDic` 0x550, `MeasureScaleData` 0x5C0, `ReadyToURL` 2077, `ez_url`
  0x820, `ezi_url` 0x828, **`bundleCryptKey` 0x830**, `patternFileInfo` 0x838.
* `InGameCore` (static `Byte[]`): `svk` 32, `svl` 16, `svm` 32, `svn` 16, `svo` 32,
  `svp` 16, `svq` 64, `svr` 16. Read statics via `il2cpp_field_static_get_value`; their
  static-region offsets alias early instance fields, so reading them off the instance
  yields garbage.
* `da` statics: `aes_key` = `91534567190123456709012745679903`, `aes_iv` =
  `0173456089512849` (AES-256-CBC/PKCS7, key/IV used as **ASCII**; verified —
  `da.AESEncrypt("AAAA")` → `CLbb9g2E8onb853oZrILYQ==`).
* `qe` statics: `aes_key` = `31274527810126456489012345678909`, `aes_iv` =
  `9824450789003347`.
* `bbk` statics: `wdp` (32 B) = `ce2e2185e0cde39d3ef798e1678b950e7ac9f7014307a04aed8c4faabe3e58f0`,
  `wdq` (16 B) = `a5cf61a270f467ca7611cfae8bd364a5`.
* `da.rpr` = API base; `da.ror` / `da.ros` = client version / build.

### 4.4 Symbolication & code scanning

* `tools/il2cpp/_sym.js` — enumerate all 176,021 methods (97 assemblies) →
  `virtualAddress → Class.method` (~8 s).
* `tools/il2cpp/_callers.js` — **the workhorse.** Scans the whole module for direct `E8`/`E9`
  rel32 call/jmp sites targeting given VAs, builds its own 176,021-method symbol map, and
  attributes every hit to its enclosing method (nearest preceding method VA). Full sweep
  ≈40 s. This is what located the chart decryptor (`dcf`, and its `jmp` to `dcg`).
  Supersedes `_findcallers.js`, which had a hardcoded, per-launch-stale module base.
* `tools/il2cpp/_findcallers.js` — older fixed-base variant; kept for reference.
* `tools/il2cpp/_staticscan.js` — the correct IL2CPP static-access signature:
  `mov r64,[r64+0xb8]` then `add r64, imm32`. Scanning the displacement form instead
  yields ~90× false positives.
* `tools/il2cpp/_encl.js` — standalone enclosing-method attribution; `_callers.js` now
  does this inline.

### 4.4.1 Virtual dispatch is resolvable after all

IL2CPP virtual calls do **not** go through an opaque thunk. The codegen loads a
`(methodPtr, methodInfo)` pair straight out of the klass struct:

```asm
mov r8, [obj]            ; klass  (object header @ +0)
mov r9, [r8 + SLOT]      ; methodPtr
mov r8, [r8 + SLOT + 8]  ; methodInfo
call r9
```

So a virtual call site is a plain `mov reg,[reg+disp32]` — scannable, given the slot.
Slots are **not** globally unique (they are per-class), but **inherited slots keep their
offset in derived classes**. For anything deriving from `SymmetricAlgorithm`:

| slot | method |
|---|---|
| `0x1a8` | `set_BlockSize` |
| `0x1d8` | `set_IV` |
| `0x1f8` | `set_Key` |
| `0x238` | `set_KeySize` |
| `0x258` | `set_Mode` |
| `0x278` | `set_Padding` |

Find a slot with `tools/il2cpp/_slotfind.js` (dumps the klass struct and locates a method’s
VA at its 8-byte-aligned offset). Reading a klass correctly requires the Il2CppClass layout
— `name`@0x10, `namespaze`@0x18, `static_fields`@0xb8 — via `_probe_cls.js` / `_mem.js`.

> **JS gotcha that cost time:** `x >>> 32` is `x >>> 0` in JavaScript (shift counts are mod
> 32). Use `Math.floor(x / 4294967296)` for the high word of a 64-bit address.

### 4.4.2 Static fields

`tools/il2cpp/_statics.js` lists a class’s static fields with static-region offset, type,
and live length/head for `Byte[]` values. This is how the chart key was extracted:
`InGameCore` statics `svq`(64)/`svr`(16) are the mask tables and `svo`(32)/`svp`(16) are the
AES key/IV. Related: `_mem.js` (raw reads, klass name, byte-array dumps),
`_methods.js` (method VA + field offset listing), `_vt.js` (crypto-class VAs + module base).

### 4.5 Metadata

`global-metadata.dat` (26,226,972 B) has **no `0xFAB11BAF` magic**, so Il2CppDumper aborts.
Only part of the file is obfuscated; from ≈18.2 MB it contains plaintext type/method/field
names (which is how the DTO structure was recovered). The AOT machine code is **not**
needed from it — it is readable directly from process memory.

## 5. Tools

User-facing (repo root):

| Tool | Purpose |
|---|---|
| `extract_assets.py` | extract keysounds (FLAC/OGG) and `--bga` videos |
| `find_bundle.py` | map bundles → songs (`--index`, `--decrypt`) |
| `decrypt_all.py` | bulk bundle decryption with `true_key_1024.bin` |
| `harvest_key.py` | derive `true_key_1024.bin` from live memory |
| `harvest_chart.py` | watch `InGameCore` for chart URLs and fetch them |
| `decrypt_chart.py` | **decrypt CDN payloads** → `.ez` / `.ezi` plaintext (library + CLI) |
| `parse_chart.py` | **read decrypted charts** — `.ez` note charts and `.ezi` keysound indexes, as a summary, JSON, or note listing |
| `chart_labels.py` | **name charts** — decrypt captured API traffic into `chart_labels.json` (song name, key mode, difficulty); `dump_song.py` reads it back |
| `check_charts.py` | **audit the captures** — chart identity vs the `<keymode>/<difficulty>/` it is filed under, missing artifacts, and `ident.json` disagreeing with the chart on disk. Catches the mislabelling bug that filed a 4K chart under `5k/shd`; exits non-zero, so it can gate a batch |
| `render_song.py` | **render a song** — plays every note's keysound at its scheduled time; `--assets auto` matches keysounds by content |
| `visualize_song.py` | **visualise a render** — mp4 with keysounds, lanes and progress overlaid on the BGA; player-lane rows are bright, auto-played rows dimmed (`--no-auto-dim` to disable); bulk-renders a whole song dir or `--all`, with `--skip-existing`/`--force` |
| `harvest_metadata.py` | dump the game's song metadata table (title, composer) → `music_names.json` |
| `song_meta.py` | resolve a song's title/composer, with folding and prefix fallbacks |
| `dump_song.py` | **per-song snapshot** — byte-exact CDN archive, decrypted plaintext, `da.rus` buffers, plus the song/mode/difficulty label read from the running game. `instrumentDic.json` only with `--read-instrument-dic`; a capture is redirected to `<name>_mismatch/` when the chart disagrees with the runtime label; stops the watch when the read path dies |
| `run_dumper.sh` | Il2CppDumper (blocked by the missing metadata magic) |

Private server (see **`server/README.md`** for the full guide):

| Tool | Purpose |
|---|---|
| `server/_pserver.py` | **the private server** — a mitmproxy addon that stubs `game1-play` / `game1-rank` / `game1-cdn` server-side; no extra certs, no hosts edits (the Wine prefix already proxies through mitmproxy and trusts its CA) |
| `server/_harvest_session.py` | Frida bridge: polls `zf.aes_key`/`aes_iv` at 1 Hz → `server/session_key.json` (the client generates the API session key locally and never sends it — §3.1) |
| `server/_build_data.py` | rebuild `server/data/` from local captures — decrypted API templates, the chart→CDN map (47 variants / 15 songs), profile overrides |

Investigation tooling — layout, build step and crash warnings: **`tools/README.md`**.
Drivers are loaded as `bridge + driver` and regenerated with
`bash tools/il2cpp/build_run.sh`.

Notable: `tools/probes/_poll_da.py` (safe 4 Hz `da.rus` watcher — the pattern to copy),
`tools/crypto/_rijndael256.py` (verified Nb=8 Rijndael; `pycryptodome` cannot do it),
`tools/legacy/` (superseded first-generation scripts).

## 6. Outputs

| Path | Contents |
|---|---|
| `extracted_assets/<song_id>/` | FLAC/OGG keysounds, BGA `.mp4` |
| `extracted_charts/<song>/<keymode>/<difficulty>/` | `ident.json` (identity + label + metadata), `cdn_*.bin`, `ez.ez` / `ezi.ezi` (decrypted), `mem_rjl/rjm/rjn.bin`, `instrumentDic.json`. Nesting so each variant keeps its own capture (`destr0yer/5k/hd/`); `--name-by title` merges variants into one directory and `--name-by id` uses the music id, and an unidentifiable song falls back to `song_<hash>` |
| `EZ2ON REBOOT R/decrypted_bundles/` | decrypted `.unity3d` containers |
| `song_index.json` | bundle-hash → song/asset index |
| `true_key_1024.bin` | master bundle XOR key |
| `server/data/` | generated locally by `server/_build_data.py` — decrypted API response templates, chart→CDN path map, profile overrides. **Git-ignored**: personal data, the music DB, and key material; regenerate from your own captures |

## 7. Status & next steps

**No blockers.** Every layer is now solved: AssetBundles, keysounds/BGA, the API session
cipher, and the CDN chart/index cipher (§3.3, `decrypt_chart.py`).

**Done:** located the chart decryptor by scanning for direct calls into the `dc*` cluster
(`tools/il2cpp/_callers.js`), identified `dcf → dcg` as `mask ∘ AES-256-CBC`, extracted the
static key material (`svq`/`svr` mask tables, three key/IV pairs), and verified the result
end-to-end (5 songs, 3 key pairs). The 4K lane map and the long-note rule are verified
against the game's own `normalLanes`, 12/12 lanes exact. `parse_chart.py` reads the result:
header, tracks, note events with normal/long, `.ezi` join; JSON or a note listing.
`dump_song.py` now decrypts on capture and waits for the parse before snapshotting.
The login/session-key protocol is fully mapped (§3.1) and a **basic private server**
(`server/`) serves a complete online session — login, music list, profile, pattern files,
CDN charts, rank stubs — with the session key bridged from the running game; wire formats
verified end-to-end offline, in-game validation in progress.

**Next:**

1. Identify note types 5/6/9 against `InGameCore`'s `specialNoteData` / `autoNoteData`.
2. Find the song *name* for a chart with no API label — the header name gives the variant
   (`5-hd`) but not the song, so `dump_song.py` still falls back to `song_<hash>` there.
   (`patternFileInfo` reads empty at capture time, which is what forces the API route.)
3. Determine whether the API's `keymode` ever disagrees with the header-name / lane-count
   key mode (7K unobserved; 8K seen as `8-ez` but no API label yet).
4. Find what selects the key pair (`svk`/`svm`/`svo`) — not the payload, the CDN path, or
   `bundleCryptKey`; it looks like an authoring/build-time choice.
5. Capture a bridge-keyed session **of the real servers** (plain `mitmdump -w` **plus**
   `server/_harvest_session.py` running — the auto-reattach harvester makes the ordering
   irrelevant) to decrypt the real `c2s_set_game_clear` response (48/64 B, length varies)
   and the real `c2s_get_userinfo` response (≈832 B / 10 profiles). A first attempt
   captured the traffic but not the key — the API bodies of that dump are sealed. Also
   pins the constant `plf` fields (§3.7).
6. Make the server Frida-free: patch `zf.gnf` to a fixed session key, or RE the raw-TCP
   control/battle channel (`zf` RSA+AES) the real server presumably uses to learn the key.
7. Broaden chart coverage in `server/data/` (uncaptured songs fail with `result:0` and
   the client retries 5× before booting to the main screen — e.g. Hyper Magic 5K HD).
8. **Fully offline chart loads**: run the error-site hunt (`EZ2_HUNT=1`) and read the
   client's pattern-response validation (§3.7). If it verifies the CloudFront URL
   signature with an embedded public key, patching that key lets the private server
   mint its own signed URLs. The control channel turned out to be a Notice websocket
   (announcements only) - not a blocker.
9. Persist progression: feed accepted `plf` uploads back into the served myinfo
   `clearlist` so scores/records survive across sessions (the client computes its
   per-key-mode rating from that data — §3.7), and RE the exact per-mode rating
   formula if precise control is wanted.
