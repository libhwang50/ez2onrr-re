# EZ2ON REBOOT: R — Reverse Engineering Technical Report

Current state as of 2026-09-18. `README.md` is the user-facing guide; `tools/README.md`
covers the investigation harness. Superseded conclusions are marked *(supersedes …)*
rather than kept as narrative.

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
* Use **managed invocation** via `frida-il2cpp-bridge` (`onMain()` for anything touching
  BCL crypto — Wine/CNG thread affinity), plus **≤4 Hz host-side polling**.
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
| CDN | CloudFront `game1-cdn.ez2game.co.kr` (`Key-Pair-Id=K2L5B5JS5W46ST`); signed URLs with a **~150 s TTL** |
| Transport | WinHTTP. `mitmproxy` sees everything (Wine prefix has `ProxyEnable=1`, `ProxyServer=127.0.0.1:8080`) |
| Control channel | proprietary TCP to `3.37.247.33:4649`, `zf` RSA+AES — not needed for extraction |

### 3.1 API session cipher — CRACKED

Bodies are `data=<base64>` (request) / raw base64 (response) around **AES-CBC / PKCS7**.

* **Key** = the **32 ASCII bytes** of `zf.aes_key` (not hex-decoded); **IV** = the
  **16 ASCII bytes** of `zf.aes_iv`.
* Both are statics **overwritten at login** → session-scoped, rotating per launch. Read
  the live values with `il2cpp_field_static_get_value`, never the metadata defaults.
* Requests share a fixed 16-byte prefix (`d3ad76d3adb846d599fae4c451509c06`) — irrelevant
  for extraction.
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
| `zf.wz` | `appid`, `steamId:UInt64[]` |

* **`bundleCryptKey`** — a **96-character hex** string; `da.rus.rjn` is exactly
  `bytes.fromhex(bundleCryptKey)` (48 bytes). **Session-scoped**: byte-identical for both
  songs sampled in one session, so the earlier “per-song” reading is superseded — which
  also retracts the note that had superseded the original per-session claim. It is **not**
  the chart key (§3.3).
* **`CRYPT_KEY`** — a per-song 16-element `{1,2,3}` sequence; a chart/note-obfuscation
  parameter, **not** cipher key material.
* **Naming is correct**: `final_url_ez` = the **chart**, `final_url_ezi` = the
  **keysound index** *(supersedes the earlier “inverted” claim)*.

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
| `svk`/`svl` | Engine 4K SHD |
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
  The unit of the long-note `flags` value is unknown (it is *not* a tick count), and it has
  **no audio effect**: verified in-game that a long note's keysound plays exactly like a
  normal note's and is not sustained. The distinction must drive judgement or visuals.
* **`name` at `0x06` is not the song name** — it is an authoring tag. Observed values:
  `4-shd`, `#PTMAKE` (presumably built with the in-game pattern maker), and empty.
  Conflict and Hyper Magic are different songs that both carry `4-shd`.
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
  all of them sound. Every keysound declared in a `.ezi` is referenced by some track
  (`declared-but-unplayed` is 0), so the bank is fully sequenced by the chart.
  **Verified by ear against gameplay — reported as an exact match.**

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
`render_song.py` uses it to mix every note's keysound into an audio file. All 5 captured
songs render; Conflict (6393 events, 2719 distinct keysounds) takes ~3 s and comes out
with a normal mix profile (mean ≈ −17 dB, normalised peak). Rendering is fast enough to do
in bulk — 5 songs in 11 s (`render_song.py --all`).
* **Open: note types 5/6/9** (and 8 in some files) are undocumented; the reference
  `ezinfo` reports them as unhandled. Exposed raw by `parse_chart.py`.

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
| `render_song.py` | **render a song** — plays every note's keysound at its scheduled time; `--assets auto` matches keysounds by content |
| `dump_song.py` | **per-song snapshot** — byte-exact CDN archive, decrypted plaintext, `da.rus` buffers + `instrumentDic` |
| `run_dumper.sh` | Il2CppDumper (blocked by the missing metadata magic) |

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
| `extracted_charts/<name>_<keymode>_<levelmode>_<gamemode>/` | `ident.json`, `cdn_*.bin`, `ez.ez` / `ezi.ezi` (decrypted), `mem_rjl/rjm/rjn.bin`, `instrumentDic.json` |
| `EZ2ON REBOOT R/decrypted_bundles/` | decrypted `.unity3d` containers |
| `song_index.json` | bundle-hash → song/asset index |
| `true_key_1024.bin` | master bundle XOR key |

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

**Next:**

1. Identify note types 5/6/9 against `InGameCore`'s `specialNoteData` / `autoNoteData`, and
   find what the long-note `flags` value drives (judgement/visuals only).
2. Record the song id in `ident.json` — `patternFileInfo` is empty when read, so
   `dump_song.py` falls back to `song_<hash>` and the chart → `extracted_assets` mapping
   has to be recovered by content matching (`render_song.py --assets auto`).
3. Find what selects the key pair (`svk`/`svm`/`svo`) — not the payload, the CDN path, or
   `bundleCryptKey`; it looks like an authoring/build-time choice.
