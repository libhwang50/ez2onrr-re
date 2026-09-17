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
receives signed CDN URLs plus a per-song key, then downloads and decrypts locally.

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

* **`bundleCryptKey`** — 64-char base64 → **48 bytes**; stored as `da.rus.rjn`.
  **Per-song**, not per-session *(supersedes the earlier per-session claim — entering a
  different song changes it completely)*.
* **`CRYPT_KEY`** — a per-song 16-element `{1,2,3}` sequence; a chart/note-obfuscation
  parameter, **not** cipher key material.
* **Naming is correct**: `final_url_ez` = the **chart**, `final_url_ezi` = the
  **keysound index** *(supersedes the earlier “inverted” claim)*.

### 3.3 CDN payload cipher — OPEN

| Proven fact | Evidence |
|---|---|
| Encrypted, not a native container | XOR of two different charts is random (entropy 7.996; 0 zero-bytes in the first 256) |
| **Block cipher: CBC + PKCS7, 16-byte block** | zeroing the final 16 B → decrypt error `ErrCode: NIQQ0`; zeroing 16 B at offset 4096 → loads with one localized note change |
| No integrity check | mid-file corruption is tolerated |
| Deterministic per song, fixed IV | re-downloading a song yields byte-identical ciphertext |
| 16-byte constant header | `ct₁ ⊕ ct₂` for two songs is random **except bytes 0x00–0x0F = exactly zero** |
| Not compressed | post-decrypt deflate/gzip/bz2/lzma/lz4/brotli sweeps → 0 hits |

**Ruled out** — ~2.7 M candidate decryptions against six independent oracles (magic,
printability, PKCS7 padding validity, `sha256 == url_hash`, entropy/zero-fraction,
decompress-then-check, and a text oracle for `.ezi`):

* **Keys:** every 16/24/32-byte window of `rjn`/`bundleCryptKey` (raw, base64, hex) and
  their MD5/SHA1/SHA256/SHA512 derivations; the 26-blob `a.rn*` table; `svk`–`svr`; all
  `da`/`qe`/`zf`/`bbk` constants; 517 metadata literals; 325 `CRYPT_KEY` derivations.
* **Algorithms:** AES-128/192/256 CBC/ECB/CFB/OFB/CTR, ChaCha20, Salsa20,
  DES/3DES/Blowfish/CAST/RC2/RC4, Rijndael-128/256 (verified implementation).
* The arcade EZ2AC scheme (subtract a repeating 512-byte keystream, reverse the file) —
  tested in all modes; no `EZFF`.

**Why the decryptor is invisible to static analysis.** A complete call-site scan for
`RijndaelManaged..ctor` / `AesCryptoServiceProvider..ctor` / `Aes.Create` /
`CryptoConfig.CreateFromName` / `CreateDecryptor` finds only 12 sites — all accounted for,
**none the chart decrypt**:

| Site | Role |
|---|---|
| `da.AESEncrypt/Decrypt` | local save files (`LOAD_LOCAL_DATA`, course records, favourites) |
| `zf.AESEncrypt/Decrypt` | API / TCP session layer |
| `qe.cal/fal/fam/gvf/jqv`, `bcg/bcf/bch` | **Rewired** `UserDataStore_File` (zip + CLZF2 + AES) |
| `bbk.*` | game **string** cipher — `Aes.Create()` + base64; key `wdp` / IV `wdq`; does **not** decrypt the chart |
| `InGameCore.dcg` | inert — sets `BlockSize=256`, which CNG rejects, so it aborts on every input |
| `ZipAESTransform..ctor` | SharpZipLib |

Crypto is invoked **virtually** (`ICryptoTransform`), so call sites are structurally
unresolvable from static code; the in-process AES S-box resolves to the **managed BCL**
`mscorlib/RijndaelManagedTransform.s_Sbox` *(supersedes the “bespoke managed AES” theory)*.

**Also dismissed:** `InGameCore` statics `svk`–`svr`; `da.chn/cin/cik/cqo` (they are
`Int32->String` table getters); class `a` (a **SHA-256 hash table** — all 10,986 base64
values decode to exactly 32 bytes, so earlier sweeps that treated it as key material were
testing hashes).

**Remaining routes:** (a) breakpoint the **virtual** cipher dispatch, out-of-process
preferably, since in-process hooking crashes the game; (b) reconstruct per song from
parsed memory; (c) archive the CDN bytes as served.

### 3.4 MITM oracle — `tools/mitm/_cdn_rewrite.py`

A mitmdump addon that captures every `ez2game.co.kr` body under `mitm_live/` and can
rewrite CDN bodies on the fly via `_rewrite.json` (`op`: `none`/`zero16`/`zero32`/
`trunc16`/`trunc32`/`zeros`, plus `offset` and URL `match`). The config is re-read per
response, so experiments need no restart.

> If a rewrite hangs the loader, set `{"op":"none"}` and retry — nothing persists.

### 3.5 EZ2AC format lineage

* **`.ez` = note chart**: magic `EZFF`, `0x05` version, `0x06–0x45` internal name,
  `0x86` ticks/measure, **`0x88` initial BPM (float)**, `0x8C` track count, `0x8E` total
  ticks, `0x92` other BPM; `EZTR` per-track blocks follow.
* **`.ezi` = keysound index, and it is TEXT**: `[index] [velocity] [filename]` per line,
  velocity 0/1. Corroboration — MilK: 18,192 B ÷ 807 keysounds = **22.5 B per line**, so
  the plaintext is uncompressed text exactly as long as its ciphertext.

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
  `rjm`@0x18 (`.ezi` ciphertext), `rjn`@0x20 (the 48-byte key).
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

### 4.4 Symbolication

* `tools/il2cpp/_sym.js` — enumerate all 176,021 methods (97 assemblies) →
  `virtualAddress → Class.method` (~8 s).
* `tools/il2cpp/_findcallers.js` — scan the ~76 MB code region for `E8 rel32` call sites
  (~100 s); target keys must be `parseInt(…, 16)`-ed.
* `tools/il2cpp/_staticscan.js` — the correct IL2CPP static-access signature:
  `mov r64,[r64+0xb8]` then `add r64, imm32`. Scanning the displacement form instead
  yields ~90× false positives.
* `tools/il2cpp/_encl.js` — enclosing-method attribution; a hint only (it reports nonsense
  for sites far into a large method).

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
| `dump_song.py` | **per-song snapshot** — byte-exact CDN archive + `da.rus` buffers + `instrumentDic` |
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
| `extracted_charts/<name>_<keymode>_<levelmode>_<gamemode>/` | `ident.json`, `cdn_*.bin`, `mem_rjl/rjm/rjn.bin`, `instrumentDic.json` |
| `EZ2ON REBOOT R/decrypted_bundles/` | decrypted `.unity3d` containers |
| `song_index.json` | bundle-hash → song/asset index |
| `true_key_1024.bin` | master bundle XOR key |

## 7. Blockers & next steps

**Blocker:** the CDN chart/index cipher. The family is known (CBC + PKCS7, 16-byte block,
per-song key, fixed IV) and the key is live in `da.rus.rjn` / `InGameCore.bundleCryptKey`,
but no construction site for the transform exists in the binary and ~2.7 M candidate keys
failed. Corrupting a chart is tolerated mid-file but rejected at the final block, so a
padding oracle exists — at one crafted body per query it is not a practical recovery route.

**Next:**

1. Breakpoint the **virtual** cipher dispatch (out-of-process preferred, given that
   in-process hooking crashes the game).
2. Ship value meanwhile: `dump_song.py` for byte-exact CDN archiving, plus per-song
   reconstruction from parsed memory.
3. Validate reconstructed output against the reference EZ2AC tooling
   (`reference/ez2stuff/`, `ezinfo` / `ezins`).
