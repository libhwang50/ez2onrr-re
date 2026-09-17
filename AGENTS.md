# EZ2ON REBOOT: R - Reverse Engineering & Asset Decryption Technical Report

## 1. Environment & Architecture Overview

* **Game**: EZ2ON REBOOT: R (Unity IL2CPP 64-bit Windows executable running under Proton / Wine).
* **Sandbox Environment**: Steam sandboxed via Proton's pressure-vessel (Steam Linux Runtime); the older Bubblejail config (`~/.config/bubblejail`) is currently empty/unused.
* **Core Executable & Modules**:
  * `EZ2ON.exe`
  * `GameAssembly.dll` (Unity IL2CPP core engine)
  * `EZ2ON_Data/il2cpp_data/Metadata/global-metadata.dat`
  * `EZ2ON_Data/StreamingAssets/Packs/01/` & `02/` (Contains ~1,231 AssetBundles)

---

## 2. Reverse Engineering Findings

### AssetBundle Structure & Key Derivation
1. **Header Encryption Structure**:
   * All 1,230+ AssetBundles in `Packs/01/` and `Packs/02/` use header encryption limited to **the first 1,024 bytes (0x400 block)**.
   * From **offset 1024 (0x400) onwards**, all file contents are 100% unencrypted LZ4/LZMA compressed Unity asset structures.
2. **Master XOR Key Derivation**:
   * The encryption scheme uses a **static 1,024-byte XOR keystream** (`true_key_1024.bin`).
   * Using a zero-hook memory harvester (`harvest_key.py`) to avoid anti-cheat (`uncheatercsd.dll`) code-patching checks, we extracted the true in-memory decrypted header from RAM:
     $$\text{Key}[0..1023] = \text{RAM\_Decrypted\_Header}[0..1023] \oplus \text{Encrypted\_Disk\_Header}[0..1023]$$
   * Decrypting bundles with this master key produces 100% valid `UnityFS` headers with intact file size, compressed directory, and uncompressed metadata size fields.
3. **TextAsset & VideoClip Asset Extraction**:
   * AssetRipper's GUI exports `TextAsset` script buffers using UTF-8 string encoding, which corrupts non-ASCII binary bytes in FLAC/OGG audio files stored as `.bytes`.
   * **`extract_assets.py`** parses the `TextAsset` C++ object binary structure (`m_Name` + padded byte array offset) directly from raw object byte streams, producing 100% playable FLAC/OGG audio files (44.1kHz, 16-bit stereo).
   * **BGA Video Extraction (`--bga`)**: BGA videos (`.mp4`) stored as `VideoClip` objects in `Packs/02` are extracted cleanly by parsing `m_ExternalResources` stream offsets, outputting 720p H.264 MP4 videos.
4. **Chart Delivery Architecture & File Formats**:
   * **File Layout & Formats** (as consumed by the player, e.g. `Cpp_Mania_Player` `EZ2ONParser`):
     * `*.ezi`: Binary chart data starting with magic `EZFF` (`0x45 0x5a 0x46 0x46`), containing a 150-byte header, 78-byte channel headers, and 13-byte note/BPM event structures. Unencrypted *once reversed*.
     * `*.ez`: Plaintext keysound index mapping lines of `<id> <flag> <filename>` (flag 0 = playable keysound, 1 = BGM).
   * **InGameCore Runtime Pipeline**:
     * Chart download and initialization are coordinated in `InGameCore` using dynamic URLs fetched on demand:
       * `ReadyToURL` (`bool`, offset `0x81d`)
       * `ez_url` (`string`, offset `0x820`): Direct URL to download the `.ez` keysound map.
       * `ezi_url` (`string`, offset `0x828`): Direct URL to download the `.ezi` binary chart.
       * `bundleCryptKey` (`System.Byte[]`, offset `0x830`): decoded **session-scoped** chart key (from the `wy.bundleCryptKey` API string). Transient — populated on chart fetch, null after decrypt.
       * `patternFileInfo` (`List<zf.wx>`, offset `0x838`): Metadata containing song codename, keymode (4K/5K/6K/8K), and difficulty.
     * **Memory lifecycle (observed 2026-09-16)**: `ez_url`/`ezi_url` and the parsed chart (note/BPM data) remain in `InGameCore` while (a) playing the song for the first time, (b) paused during gameplay, or (c) on the game-over screen. They are **cleared** on quick-restart (from pause or game-over) and on continuing to the result screen. The chart is **re-fetched** each time gameplay is entered from the song-select screen, even after a clear.
     * **Per-song response DTO (`wy` = `S2C_GET_PATTERN_FILE`)** — instance fields, all `System.String` unless noted:
       * `final_url_ez` (offset `0x10`), `final_url_ezi` (offset `0x18`), `bundleCryptKey` (offset `0x20`), `result` (`System.Int32`, offset `0x28`).
     * **Request DTO (`zf.wx` = `C2S_GET_PATTERN_FILE`)**: `appid` (`0x10`), `musicresourcename` (`0x18`), `keymode` (`0x20`), `levelmode` (`0x28`), `gamemode` (`0x30`) — all `System.String`.
     * **`InGameCore` static byte-array fields `svk`–`svr`** (AES-sized session material):
       * `svk` 32 B, `svl` 16 B, `svm` 32 B, `svn` 16 B, `svo` 32 B, `svp` 16 B, `svq` 64 B, `svr` 16 B — three (AES-256 key + 128-bit IV) pairs plus a 64-byte and a 16-byte value. **Session-specific**.
       * These are **static** fields — their static-region offsets (`0x38`–`0x70`) alias early instance fields (`pushDown_lock`, `logic_Lock`, `rtr_lock`, `slm`, …). They must be read via `il2cpp_field_static_get_value`, NOT from `InGameCore.instance` (reading from the instance yields garbage).
   * **CDN Delivery & Signed-URL TTL**:
     * Charts are served from CloudFront (`game1-cdn.ez2game.co.kr`, pop `ICN57-P3`, `Key-Pair-Id=K2L5B5JS5W46ST`).
     * Signed URLs have a short **~150-second TTL** — a chart must be downloaded immediately after the URL is captured from RAM, or the request returns **HTTP 403**.
     * The **real 403 root cause is URL expiry, not headers** — the game's headers are correct and required.
   * **Anti-Cheat (XIGNCODE3 / Uncheater) — PRESENT as a managed IL2CPP assembly (2026-09-16)**:
     * No native anti-cheat module is mapped (`Process.enumerateModules()` = 83 modules; none match `uncheat|xigncode|xmag|xem|nProtect`), **but** the IL2CPP assembly set contains **`uncheatercsd.dll`** with a `SystemBins64.UNCHEATER_DATA_0` static blob. The protection therefore runs as **managed IL2CPP code** (or is manually mapped), not as a visible native DLL — the earlier “no anti-cheat at all” reading was wrong.
     * **Inline hooking is non-viable** (see HOOK SAFETY below): both an unsafe and a pointer-validated `Interceptor.attach` on `AesTransform..ctor` crashed the process on attach. Treat GameAssembly code patching as detected/hostile — **read-only memory inspection only**.
     * **HOOK SAFETY (hard lesson, 2026-09-16)**: **inline hooking via Frida is non-viable in this environment.** (a) An unsafe hook crashed the game — reading a non-pointer arg as a managed array (`ptr.add(0x18).readS64()` where the arg was the `bool encryption` flag `0`/`1`) segfaulted; Frida invalid-read handling is unreliable under Wine/Proton. (b) A **pointer-validated** hook (`_hook_aes2.js`, every arg guarded by `Process.findRangeByAddress` + span checks) on `AesTransform..ctor` **also crashed the game on attach**. Conclusion: patching `GameAssembly.dll` code is unusable here (Wine/Frida code-patch incompatibility or a self-integrity check) — **use read-only memory inspection only**.
   * **HTTP Transport (WinHTTP.dll)**:
     * The game downloads via `WINHTTP.dll` (not libcurl; the string `libcurl/8.10.1-DEV` in the UA is cosmetic). Confirmed via `mitmproxy` capture.
     * **In-process WinHTTP via Frida was abandoned**: it hangs on *every* HTTPS URL (CloudFront and google.com alike) — a Wine/Proton WinHTTP async-TLS limitation. Host-side `curl` reaches the CDN cleanly.
   * **Game Request Headers (from `mitmproxy`)**:
     * `User-Agent: UnityPlayer/6000.0.78f1 (UnityWebRequest/1.0, libcurl/8.10.1-DEV)`
     * `Accept: */*`, `Accept-Encoding: gzip, deflate, br` (`--compressed`)
     * `Content-Type: application/json` (CDN) / `application/x-www-form-urlencoded` (API)
     * `X-Unity-Version: 6000.0.78f1`
   * **Chart Payload Cryptanalysis — OPEN RESEARCH ITEM**:
     * The CDN serves the charts **encrypted, not compressed**. A successful HTTP 200 fetch of `.ezi` (69,504 bytes) begins with `7f c3 b5 03` (not `EZFF`); `.ez` (99,248 bytes) begins with `89 99 fa 33` and is binary, not plaintext. Since both were captured via `mitmproxy`, **the bytes on the wire are the ciphertext** — the game decrypts locally after download.
     * Statistical profile (both files) is indistinguishable from random and 16-byte aligned:
       * Shannon entropy `7.998` (`.ez`) / `7.997` (`.ezi`); all 256 byte values present.
       * χ² (df=255) ≈ `238` / `246`; zero-byte counts `395` / `266`.
       * Sizes are exact multiples of 16 (`99,248 = 16×6203`, `69,504 = 16×4344`).
       * **No repeated 16-byte block**, **no repeated 8-byte window**, and global IC = `0.003906` (random baseline) → no keystream periodicity.
       * `IC(ez XOR ezi) ≈ 0.003906` → the two files **do not share a keystream/nonce** (rules out a misused reused-key stream cipher).
     * **Ruled out by direct test** (at offsets 0/4/8/16, alone and after all bundle-key XOR variants):
       * gzip, zlib, raw-deflate, bz2, LZMA (alone/xz/raw), LZ4, Zstd, Brotli, Snappy.
       * Single-byte XOR; XOR with `true_key_1024.bin` (full, first-0x400-only, and first-block variants); all rotations of the bundle key.
       * AES-ECB (no repeated 16-byte blocks). Unity container signatures (`UnityFS`/`UnityWeb`/`CAB-`/`LZ4`/`LZMA`) are absent.
     * **Conclusion**: consistent with a **block cipher of AES class** (uniform entropy + 16-byte block alignment + zero repeats). The key is the session-scoped **`bundleCryptKey`** returned by the chart-dispatch API (see “API Session Cipher — CRACKED” below).
     * **`bundleCryptKey` brute-force (2026-09-16)**: the live `bundleCryptKey` (48 bytes) was tested against **same-session** CDN ciphertext across CBC/CFB/OFB/CTR/ECB × key lengths 16/24/32 taken from **every sliding window** of both its raw (48 B) and ASCII (64 B) forms, plus MD5/SHA1/SHA256/SHA512 derivations and many IV sources — **0 `EZFF` hits**. The exact CDN key/IV derivation therefore remains unresolved and is being captured live via an `AesTransform..ctor` hook.
     * **Red herrings dismissed**: the `InGameCore` static `svk`–`svr` byte arrays and the per-song `CRYPT_KEY` string are **not** AES cipher keys (see below).
   * **Chart API & Per-Song Key Discovery**:
     * The API base is embedded in `global-metadata.dat` @ `18235263`: `https://game1-play.ez2game.co.kr/api/` (plus a test host `https://game1-test99.ez2game.co.kr/api/` and basic-auth reporting URLs `https://<id>@m4rb.ez2game.co.kr/`). `game1-cdn.ez2game.co.kr` is CloudFront.
     * API DTO field cluster @ ≈`24893925`: `appid`, `musicresourcename`, `keymode`, `levelmode`, `gamemode`, `final_url_ez`, `final_url_ezi`, **`bundleCryptKey`**.
     * Crypto-related strings/types: `AES_KEY`, `AES_IV`, `CRYPT_KEY`, `musicList`; classes `TCP2025_Client.Util|AesManager`, `TCP2025_Client.Util|AesKeyJson`, `TCP2025_Server.Util|RsaManager`, `WebManager|C2S_GET_PATTERN_FILE`, `WebManager|S2C_GET_PATTERN_FILE`.
     * **Corrected model (2026-09-16)**: the HTTPS `WebManager` API is **fully encrypted** with a *session* AES key (see “API Session Cipher — CRACKED”). `c2s_get_gameinfo` returns the music list (1,201 entries, each with a `CRYPT_KEY`); `c2s_get_pattern_file` returns `final_url_ez`/`final_url_ezi` + **`bundleCryptKey`**. `bundleCryptKey` is **identical for every song/difficulty within a session** → it is a **session-scoped** key, **not** per-song.
     * **`bundleCryptKey` (response DTO `wy`, offset `0x20`)**: a 64-char Base64 string → **48 bytes** (e.g. `BgpE/G7d3K5q/q831Rp0Zat6X7EepFML+RA13+CDHYoJorvN1YAxfb/Ousio2djw` → `060a44fc…d9d8f0`). Identical across all 10 captured songs.
     * **`CRYPT_KEY` (music-list entries `wa`/`wb`)**: a per-song **16-element sequence of digits `{1,2,3}`** (e.g. `2,2,1,3,3,1,1,1,2,3,2,1,3,1,1,3`) — a chart/note **obfuscation parameter**, **not** AES key material. All 1,201 entries have a unique value.
     * **Music-list entry schema** (decrypted `c2s_get_gameinfo`): `MUSIC_ID`, `TITLE`, `TEMPO`, `MIN_TEMPO`, `MAX_TEMPO`, `VERSION`, `LEVEL` (comma list), `NOTE` (comma list), `CRYPT_KEY`, `JUDGEMENT_TIME`, `GAUGE_RATE`, `DLC`, `GAME_MODE`, `RATING_CATEGORY`, `SUB_DLC`, `LINK_TYPE`.
     * **Runtime-confirmed statics** (read via `il2cpp_field_static_get_value`, 2026-09-16):
       * `zf.aes_key` / `zf.aes_iv` are the **API session key/IV** and are **overwritten at login** via the field setter (metadata holds only the pre-login defaults `4A6469F1358147858EFD430E44FD8A57` / `F8BECB8836AFA814`). Observed live this session: `C7E3C35D846086B6610CF7DEE4F0A192` / `BAE5707397612215`. `zf.publicKey` = 2048-bit RSA `<RSAKeyValue>` (TCP session layer).
       * `da.aes_key` = `91534567190123456709012745679903`, `da.aes_iv` = `0173456089512849`; `qe.aes_key` = `31274527810126456489012345678909`, `qe.aes_iv` = `9824450789003347` (ASCII 32/16 chars; default constants).
       * `da.rpr` = `https://game1-play.ez2game.co.kr/api/`, `da.rps` = `https://game1-test99.ez2game.co.kr/api/`, `da.rpv` = `3.37.247.33:9902`, `da.ror` = `2026.09.04.001`, `da.ros` = `A2`.
       * Member DTO is `zf.vy.vx` (class `vx`), held by `vy.member` (instance field, offset `0x18`); `vy` = the login/myinfo response (`apps`, `member`, `result`) and is transient (GC'd after processing). `vx.AES_KEY`/`vx.AES_IV` are `System.String` fields at offsets `0x40`/`0x48`.
   * **Network MITM (`mitmproxy`) — Partial Visibility**:
     * The **HTTPS** traffic (API + CloudFront CDN) **is** visible to `mitmproxy`; this is how the request headers and the two encrypted chart files were obtained. `curl` to `https://game1-play.ez2game.co.kr/api/` and `https://game1-cdn.ez2game.co.kr/` returns `HTTP 403` without the game's valid request context/signature.
     * Control and chart-dispatch signalling additionally flows over a proprietary TCP connection to `3.37.247.33:4649` (AWS ap-northeast-2) managed by session class `zf`, encrypted end-to-end (`zf.AESEncrypt`, `zf.AESDecrypt`, `zf.RSAEncrypt`) → not parseable via transparent proxy without the session crypto keys.
     * **NOTE**: no `mitmproxy` flow files were persisted to disk (only the CA material in `~/.mitmproxy`), so captured API JSON containing `bundleCryptKey` is **not** currently available and must be re-captured.

### API Session Cipher — CRACKED (2026-09-16)

The `game1-play.ez2game.co.kr` HTTPS API is **not plaintext**: every request/response body is `data=<base64>` (request) or raw Base64 (response) wrapping a session AES cipher. It was cracked from the captured `mitmproxy` flows (`flow_dumps`) plus the live `zf` statics.

* **Cipher / mode**: **AES-CBC**, **PKCS7** padding (matches Mono's managed `AesTransform`).
* **Key**: the **32 ASCII bytes** of the `zf.aes_key` string (e.g. `C7E3C35D846086B6610CF7DEE4F0A192` → 32 bytes; **not** hex-decoded).
* **IV**: the **16 ASCII bytes** of the `zf.aes_iv` string (e.g. `BAE5707397612215` → 16 bytes).
* **Key origin**: `zf.aes_key`/`zf.aes_iv` are populated at login (metadata statics are defaults); they are **session-scoped** and rotate per launch.
* **Verified plaintexts**:
  * `c2s_login` → `{"apps":[…],"member":{MEMBER_ID,NICKNAME,DLC,STEAM_ID,PLAY_COUNT,WIN_COUNT,LOSE_COUNT},"result":…}`
  * `c2s_get_myinfo` → `{"memberinfo":{…},"config":{…},…}`
  * `c2s_get_gameinfo` → `{"musicList":[…1201 entries…],…}`
  * `c2s_get_pattern_file` → `{"final_url_ez":…,"final_url_ezi":…,"bundleCryptKey":…,"result":1}`
* **Requests**: request bodies use the same suite but with a fixed 16-byte prefix (`d3ad76d3adb846d599fae4c451509c06`; Base64 begins `06120624RtWZ+uTEU…`) shared across requests — evidence of a fixed IV/keystream for requests. **Not required** for chart extraction and left uncracked.
* Offline decryptors: **`_decrypt_api.py`** (pattern responses → `bundleCryptKey`) and **`_decrypt_api_all.py`** (all response types).

### Metadata Obfuscation & Il2CppDumper Blocker

* `global-metadata.dat` is **26,226,972 bytes** and starts with `e355ceea2fc2cc3b1a35d656a833e1b3…` — the IL2CPP header magic `0xFAB11BAF` is **absent**, so `Il2CppDumper` aborts with `ERROR: Metadata file not found or encrypted.`
* The file is only **partially** encrypted/obfuscated:
  * `0x00`–≈`0x8C0000` (0–9.2 MB): high entropy (`7.997`).
  * ≈`9.3`–`9.6` MB: low entropy (`~5.0`).
  * `9.7`–`18.2` MB: high entropy.
  * From ≈`18.2` MB onward: mixed regions containing **plaintext** type names, method names and field-name strings (e.g. `bundleCryptKey`, `AES_KEY`, `C2S_GET_PATTERN_FILE`).
* The full AES forward S-box (`637c777b…bb16`) is present in the metadata at offsets **`19018904`** and **`19161584`** (the second followed by inverse T-table-like data). These belong to the **Mono BCL** managed AES, not a bespoke game cipher — confirmed at runtime: the only classes exposing a 256-byte static S-box are `mscorlib.dll!System.Security.Cryptography.RijndaelManagedTransform.s_Sbox` and `System.Core.dll!System.Security.Cryptography.AesTransform.SBox`. The game's `Tcp2025/AesManager.cs` drives the BCL AES.
* **Plaintext source paths** (metadata strings, ≈18.3 MB): `Assets/Scripts/Tcp2025/AesManager.cs`, `AesKeyJson.cs`, `RsaManager.cs`, `JsonParameter.cs`, `ServerManager.cs`; original namespaces `TCP2025_Client.Util` (`AesManager`, `AesKeyJson`) and `TCP2025_Server.Util` (`RsaManager`, `RsaKeyJson`, `RsaJsonConverter`).
* **Blocker (reduced)**: `global-metadata.dat` remains unreadable on disk (no `0xFAB11BAF`), so `Il2CppDumper` still fails. **However, the AOT machine code is NOT required to be read from the metadata**: it is readable directly from process memory (see below).

### Managed Method Invocation — `frida-il2cpp-bridge` (2026-09-17)

`frida-il2cpp-bridge@0.14.0` (vendored as **`_il2cpp_bridge.js`**, ~167 KB, from unpkg) runs in the Frida Gadget and can **list assemblies/classes and invoke arbitrary managed methods without patching any code** (anti-cheat-safe).

* **Driver pattern**: concatenate `_il2cpp_bridge.js` + a driver that defines `rpc.exports.*`, run via `sc.exports_sync.<fn>()`. Get the bundle’s classes with `Il2Cpp.domain.assembly("Assembly-CSharp").image`.
* **Gotcha**: the driver’s helper functions are not visible inside `Il2Cpp.perform(() => {...})` — **inline everything** inside the callback.
* **CRITICAL — Wine/CNG thread affinity**: any method that touches the OS crypto provider (BCL AES) **SIGSEGVs (`system error`) when called from Frida’s thread under Proton**. Fix: run the call on the **game’s main thread**:
  ```js
  function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
  ```
  `Process.runOnThread` returns a Promise, but `Il2Cpp.perform` awaits it. This is a Wine/CNG limitation, **not** anti-cheat.
* **`invokeRaw` uses the raw native function pointer**, not `il2cpp_runtime_invoke` → a managed exception thrown inside a method **aborts the process** (`system error`). Expect that for methods given malformed input (e.g. `qe.fao` on a non-ZIP).
* **Code IS decrypted in memory** (corrects the earlier §2 note): methods run, and `Il2Cpp.Method.virtualAddress` points at valid x86-64. Sampling `GameAssembly.dll` at RVAs in the **`il2cpp` section (RVA ≈ `0x3db000`–`0x363d000`, ~52 MB)** gives entropy ≈ 6.1–6.5 and sensible disassembly (e.g. standard IL2CPP class-init guards). Only part of the later `.text` (RVA `0x48f6000`+, 23.8 MB) is still high-entropy. `il2cpp_code/*.bin` holds 4 KB dumps per method (`_dump_code.js`).

### Live Runtime State (2026-09-17)

* **`da` = the game’s AES helper**: `da.AESEncrypt(String)->String` / `da.AESDecrypt(String)->String` (both **static**, base64 in/out). Scheme **verified offline**: **AES-256-CBC / PKCS7**, key = **32 ASCII bytes** of `da.aes_key` = `91534567190123456709012745679903`, IV = **16 ASCII bytes** of `da.aes_iv` = `0173456089512849`. (`da.AESEncrypt("AAAA")` → `CLbb9g2E8onb853oZrILYQ==`, reproduced exactly.)
* **`qe` = the AesManager MonoBehaviour** (`Il2Cpp.Field`: static `instance:qe`, `aes_key` = `31274527810126456489012345678909`, `aes_iv` = `9824450789003347`). Method map:
  * `qe.fan(byte[])->byte[]` = **zip/compress** (SharpZipLib `ZipOutputStream`, GUID entry name, ZIP64 extras, no EOCD until closed); `qe.fao(byte[])->byte[]` (static) = **unzip**.
  * `qe.fah(byte[])->String` = **wrap/unwrap a key blob**: output is a random **96-byte** (128-char base64) blob for any input size → session key exchange, *not* a file cipher. `qe.faf(String)->byte[]` is its inverse. `qe.fae(byte[])->String` = bytes→ASCII string.
  * `qe.kha/gef/gth` (instance) and `qe.lrw` (static) are `byte[]->byte[]` but **crash on any input tried** (raw ciphertext or 16 zero bytes), even on the main thread.
* **`da.rus` — the live pattern holder** (a static `da.co` at **static offset 840 (0x348)**, slot `0x64f72dc8`, `staticFieldsData` `0x64f72a80` — verified: the bridge’s static `Field.offset` **is** correct, confirmed against `aes_iv` (offset 1088) and `rop` (offset 16)). Fields: `rjl` = the `.ez` **ciphertext**, `rjm` = the `.ezi` **ciphertext**, `rjn` (48 B) = the **per-song key**. `da.co` is a 3×`System.Byte[]` record; its 10 zero-arg `byte[]` getters are plain accessors for these three fields. `da.rus` is **null on the song-select screen** and populates only when a song is entered.
* **CORRECTION (2026-09-17): `rjn` / `bundleCryptKey` is PER-SONG, not per-session.** Entering a second song changes it completely:

| | Conflict 4K SHD | Destr0yer 4K SHD |
|---|---|---|
| `rjl` (`.ez`) | 89,648 B, `a73b6ebc1c60c0ea…` | 51,216 B, `01d681fd2a00aff9…` |
| `rjm` (`.ezi`) | 89,888 B, `79de577c8f124e79…` | 49,824 B, `ff27b00b9faeb14a…` |
| `rjn` (key) | `59fa30a6e08ee514b6ddcd417b439602b9489e9a09e5d6fb18526de542b0adea5ec1e19033ee873313adb5342c3aaf50` | `6598253031c017fcfe543c03c49eb258a5297ba2b46090e108641914715cd51beb1ab40cdce0361865f78ffa9f5077b8` |

  This **explains why the CDN ciphertext is constant per song** (`da.rus.rjl`/`rjm` for Conflict were byte-identical across sessions): the ciphertext is content-addressed by a **fixed per-song key**, not a per-session one. The earlier “per-session” conclusion came from only ever comparing the *same* song across sessions. `rjn` therefore **is** the per-song key, and the remaining unknown is the transform that consumes it (AES/ChaCha20/Salsa20 with every 16/24/32-byte slice of `rjn` as key/IV, plus `rjn` unwrapped one layer by `da`/`qe`/`zf`/`a.rn*` constant keys, all tested → **0 hits**).
* **`.flac.bytes` ASCII strings (~9,273 hits) are Unity asset paths**, not the `.ez`; scanning rw- memory for ASCII `00-MR`, `EZFF`, or `PK\x03\x04` returns **0 hits** — the decrypted `.ez`/`.ezi` is not retained in a latin1/UTF-8 buffer.

### The `da.rus` Data Flow — RESOLVED (2026-09-17)

`da.rus` is a `da.co` record holding the downloaded pattern bytes plus the per-song key. Full call-graph:

* **`da.co` layout** (`da.co.fhj` / `_cova.js`): `rjl` = `System.Byte[]` **@0x10**, `rjm` = `System.Byte[]` **@0x18**, `rjn` = `System.Byte[]` **@0x20**. `da.co..ctor(3)` = `0x6ffff2a6a160`. The 0-arg `byte[]` getters are aliases: `bnh`/`un`/`jab`/`ced` → `rjl`, `cah`/`cee`/`gxs` → `rjm`, `cef`/`hlp` → `rjn`.
* **Construction** — the **only** caller of `da.co..ctor` in the entire binary is **`0x6ffff2fa1272`**:
  ```asm
  add rax, 0x830            ; InGameCore.bundleCryptKey
  mov r9,  [rsp+0xdef8]     ; r9 = bundleCryptKey
  mov r8,  [rsp+0xdf00]     ; downloaded byte[] #2
  mov rdx, [rsp+0xdf08]     ; downloaded byte[] #1
  call 0x6ffff2a6a160       ; da.co..ctor(rjl, rjm, rjn)
  mov [rax], rcx            ; da.rus = new da.co
  ```
  i.e. **`rjl`/`rjm` = the two downloaded clip buffers, `rjn` = `InGameCore.bundleCryptKey`**.
* **Secure wipe** — `0x6ffff2a6a2a0` is **`da.co.fhj`** (aliased as `cec`/`epf`): it runs `Array.Clear` over `rjl`, `rjm` **and `rjn`**, then the caller sets `da.rus = null`. **This is why no ciphertext, key or plaintext survives in memory** and why every `EZFF`/`PK` scan fails.
* **Key relay** — at `0x6ffff2f9cc4d`/`0x6ffff2f9cc6f` the code reads `da.rus.cee()` (`rjm`) and `da.rus.cef()` (`rjn`) and writes the latter back into **`InGameCore.bundleCryptKey` (offset `0x830`)**.
* **Accessor usage is minimal** — a full call-site scan of `bnh`/`cah`/`cef`/`fhj` finds exactly **two** callers: `0x6ffff2f9cc4d` (`ft` region, key relay) and `0x6ffff324920d` (`ed.MoveNext`, the wipe). So the pattern bytes are otherwise read **directly by field offset**, never via the getters.
* **`ed.MoveNext`** (`0x6ffff3249090`) is the song-end cleanup coroutine: it checks `da.rus != null`, calls `da.co.fhj` (wipe), nulls `da.rus`, then runs `da.cqo`, `da.SAVE_LOCAL_DATA`, `Resources.Load` etc.
* **Still not located**: the step that turns `rjl`/`rjm` into plaintext. See “CDN Payload Cipher — STATUS” below.
* **⚠️ CORRECTION (2026-09-18) — `da.rus` is NOT on the chart data path.** A probe experiment replaced `da.rus` with a synthetic `da.co` whose three `byte[]`s were filled with a 16-byte marker, then entered and exited a song. Result: the game **loaded and ran the song perfectly with garbage in `da.rus`**, then set `da.rus = null` on exit and *never built a new `da.co`*. So `da.rus` is a **transport/audit record** (it exists so the key can be relayed into `bundleCryptKey` and so `da.co.fhj` can securely erase the buffers), **not** the object the chart is parsed from. Its buffers are written once and then deliberately wiped.
* **`InGameCore.dcf` / `dcg`** are **static `(byte[],byte[],byte[])->byte[]`**. `dcf` is not crypto (modulo arithmetic). **`dcg` *is* an AES routine** — it sets `KeySize=128`, **`BlockSize=256`**, `Key=arg2`, `IV=arg3`, `Mode=CBC`, `Padding=PKCS7` on an `AesCryptoServiceProvider`. **It is inert**: it aborts on *every* input, including 16/32/48-byte valid-shaped ones, because `AesCryptoServiceProvider` (Windows CNG) cannot accept a 256-bit block. So `dcg` is dead code and **not** the live chart decrypt.
* `bbl` is an `AesKeyJson`-style DTO (`<Key>k__BackingField@16`, `<Iv>k__BackingField@24`, both `System.String`). Scanning rw- memory for its class pointer yields only class-table false positives (no live instance with readable `Key`/`Iv`).
* **`zf.wy`** (the `S2C_GET_PATTERN_FILE` DTO) is `final_url_ez:String@16`, `final_url_ezi:String@24`, **`bundleCryptKey:String@32`**, `result:Int32@40`. So the per-song key **arrives as the 64-char base64 string** and is decoded to the 48-byte `rjn` somewhere in between. `zf.wx` (the music-list entry) is Strings only; `zf.wz` is `{appid, steamId:UInt64[]}`.
* `qe.fah`/`faf` aside, the only other `String->byte[]` producers are `bbn.gvj/fnb/cfp/chu` (untested).

### CDN Payload Cipher — STATUS (2026-09-18)

**The payload is genuinely encrypted** — hypothesis “it is a plaintext native container” is **rejected**:

* XOR of two *different* 4K SHD `.ezi` files (Conflict 89,888 B vs Destr0yer 49,824 B) gives **0 zero-bytes in the first 256** and entropy `7.9962` (random baseline `7.9962`). Any native format would share at least a magic/version/keymode header.
* **Deterministic with a fixed IV**: re-downloading the same song yields byte-identical ciphertext (5 such identical groups exist among `mitm_parsed/cdn_*.bin`). The old “two `.ez` files share the first 464 bytes” clue was simply the *same song fetched twice* — not two songs sharing a key.
* **Not compressed**: deflate (raw/zlib/gzip), bz2, lzma (alone/raw), LZ4 (block + frame), Brotli — all offsets 0–32 on all four `da.rus` buffers → **0 hits**.
* Both files are 16-byte aligned (`.ezi` also 32-aligned); sizes scale with content.

**Complete AES/Rijndael construction inventory.** A call-site scan for `RijndaelManaged..ctor` + `AesCryptoServiceProvider..ctor` finds exactly **12** sites — `da.AESDecrypt`, `da.AESEncrypt`, `qe.cal`, `qe.fal`, `qe.fam`, `qe.gvf`, `qe.jqv`, `zf.AESDecrypt`, `zf.AESEncrypt`, `InGameCore.dcg`, `ZipAESTransform..ctor`, `CryptoConfig.CreateFromName` (plus `AesManaged..ctor` and `CryptoConfig` as factories). **None is a chart decrypt.** Note crypto calls are **virtual** (`CreateDecryptor`/`TransformFinalBlock` via vtable), so direct call-site scanning structurally cannot see them — only the constructors are findable.

**Rijndael-256 implemented and verified** (`_rijndael256.py`, `_rijsearch.py`): Nb=8 (32-byte block), Nk=4, Nr=14, ShiftRows `{0,1,3,4}`, column-first state. The Nb=4 path reproduces the FIPS-197 vector `69c4e0d8…` exactly, and the Nb=8 design is cross-checked against `mjosaarinen/rij256-rv` (`ref/testvec.txt`). Round-trip verified.

**Padding-oracle key search → 0 hits.** PKCS7 validity of the *final* block depends only on the **key**, never the IV, so it is a cheap high-confidence filter. Across **1,519 candidate keys** — every 16/24/32-byte window of `rjn`, its base64/hex forms, MD5/SHA1/SHA256/SHA512 windows of all of those, the 20 `a.rn*`/`a.rov` blobs, and every other song's `bundleCryptKey` — required to validate on **both** files (≈1/65536 false-positive rate): **0 survivors.**

**Bespoke AES likely.** The full AES S-box exists in the process only as **metadata static-field-initialiser blobs** (25 matches for the forward S-box, 24 for the inverse; their “klass” words are packed data, not pointers, and they are *not* live managed `byte[]` objects on the GC heap). Combined with the absence of any BCL crypto in the chart path, this points to a **game-supplied managed C# AES implementation with `byte[] SBox = {…}` field initialisers** — which is exactly why the tables live in `global-metadata.dat` (offsets 19018904 / 19161584) and not in `GameAssembly.dll`.

**Relevant `InGameCore` instance field offsets** (`_igc_run.js`): `normalNoteData` 1296 (0x510), `longNoteData` 1312 (0x520), `bpmNoteData` 1344 (0x540), `instrumentDic` 1360 (0x550), `MeasureScaleData` 1472, `ReadyToURL` 2077, `ez_url` 2080, `ezi_url` 2088, **`bundleCryptKey` 2096 (0x830)**, `patternFileInfo` 2104. Note the top `[reg+0x510]` referrers are gameplay/UI (`InGameCore.daq` is a per-note gameplay handler), **not** parsers.

### MITM Oracle — WORKS, no integrity check (2026-09-18)

The game's HTTPS traffic is MITM-able because the Wine prefix has WinINET proxy set (`ProxyEnable=1`, `ProxyServer=127.0.0.1:8080`) and mitmproxy's CA is trusted. **`_cdn_rewrite.py`** (mitmdump addon) captures every `ez2game.co.kr` body under `mitm_live/` and can rewrite CDN bodies on the fly via `_rewrite.json` (`op`: `none`/`zero16`/`zero32`/`trunc16`/`trunc32`/`zeros`, optional `offset`, optional `match` on the URL path). It re-reads the config per response, so experiments need **no restart**.

**Result: the payload is NOT integrity-checked.** Zeroing 16 bytes at offset 4096 of the chart produced *localized* damage — exactly one lane lost exactly one note (`[166,180,171,167]` → `[166,179,171,167]`, `instrumentDic` unchanged at 807) and one long note got a broken end time (manifested in gameplay as an infinite long note). Zeroing the first 16 bytes instead **hangs the loader**, so the 16-byte prefix is load-bearing while the rest is not hashed. **Therefore a chosen-ciphertext oracle is available.**

> ⚠️ If a rewrite hangs the loader, set `{"op": "none"}` immediately; the next retry (or a trip back to song select) recovers. Nothing persists — only the in-flight bytes were altered.

### Which CDN object is which — resolved (2026-09-18)

> **Not “inverted”** — the API's naming is correct and matches EZ2AC conventions (see “EZ2AC format lineage” above). What was inverted were *my* own labels. Evidence: corrupting the **56,000-byte** object broke a *long note in the chart*, while the keysound dictionary count was untouched. Sizes agree (18,192 B ÷ 807 keysounds = **22.5 B/line** = a text line; 56,000 ÷ 807 = 69 B/entry is absurd).

| CDN object | API field | actual content | MilK 4K SHD size |
|---|---|---|---|
| `fb_2/ec/cc37e2…` | `final_url_ez` | **the CHART** (`EZFF` note data) | 56,000 B |
| `fb_2/63/164258…` | `final_url_ezi` | **the keysound index** (**text**) | 18,192 B |

The CDN path hash is 64 hex chars (SHA-256 sized) but is **not** `sha256(downloaded bytes)`. Whether it is `sha256(plaintext)` is unconfirmed — a ~2.7M-candidate search hashed both the decrypted bytes and their decompressions against it with **0 matches**.

### `bbk` — a game class with a HARDCODED AES-256 key + IV (2026-09-18)

Found by enumerating classes that declare a static `System.Byte[]` field. **`Assembly-CSharp/bbk`**:

| field | value |
|---|---|
| `wdp` (static `Byte[]`, 32 B) | `ce2e2185e0cde39d3ef798e1678b950e7ac9f7014307a04aed8c4faabe3e58f0` — **AES-256 key** |
| `wdq` (static `Byte[]`, 16 B) | `a5cf61a270f467ca7611cfae8bd364a5` — **IV** |
| `wdr` (static `String`) | `zi4hheDN450+95jhZ4uVDnrJ9wFDB6BK7YxPqr4+WPA=` = base64(`wdp`) |
| `wds` (static `String`) | `pc9honD0Z8p2Ec+ui9NkpQ==` = base64(`wdq`) |

Its 9 methods are all `String->String` (`gpe`, `gvb`, `gvc`, `nuc`, `fki`, `mum`, `cwx`, `nc`, `nrf`) and are exactly the `bbk.*` entries that my earlier `RijndaelManaged`+`CryptoStream` call-site scan found — I had wrongly filed them under “Rewired”. So **`bbk` is the game's string-obfuscation cipher**, not the chart cipher (`wdp`/`wdq` do **not** decrypt the chart under CBC/ECB/CFB/OFB at offsets 0/16/32).

**Methodology note:** static field values read as `ERR`/null until the class is initialised. Calling a static 0-arg method (`bbk.gva()`) forces it. `fxr()` aborts, `gva()` works. Since chart loading already exercised the chart path, that class's statics should already be live.

### Cipher search status — exhaustive negatives (2026-09-18)

~**2.7M candidate decryptions** tested with several independent oracles, **0 hits**:

* Key sources: 11,211 base64/ASCII candidates from the 15,722-entry `a` string table; every class's static `Byte[]` (60 found) and base64-looking static `String` (512 found); `rjn`/`bundleCryptKey` windows and MD5/SHA1/SHA256/SHA512 derivations; the 26-entry `a.rn*` table; `svk`–`svr`.
* Modes: AES-128/192/256 CBC/ECB/CFB/OFB (+CTR), ChaCha20/Salsa20, DES/3DES/Blowfish/CAST/RC2/RC4; Rijndael-128/256 (verified implementation).
* Offsets 0/16/32 (16-byte plaintext-prefix hypothesis), IVs = zero / key-prefix / ciphertext-prefix / `rjn` windows.
* Oracles: `EZFF`/`PK` magic · printable-ASCII fraction · **PKCS7 padding validity** (key-only, content-independent) · **`sha256 == url_hash`** · **entropy & zero-byte-fraction** (a real chart should be structured, ~5–25 % zeros) · **decompress-then-check** (zlib/gzip/raw-deflate/bz2/lzma/lz4/brotli).

Best candidate scores 0.0072 zero-fraction / 7.98 entropy — indistinguishable from random. Note that **compression was previously “ruled out” by testing the raw ciphertext, which is meaningless**; the correct test (decrypt, *then* decompress) is now covered and also negative.

### 🎯 CIPHER FAMILY CONFIRMED: CBC + PKCS7, 16-byte block (2026-09-18)

Established with the MITM oracle by comparing two corruptions of the **chart**:

| probe | result |
|---|---|
| zero 16 bytes at offset **4096** (mid-file) | **loads**, localized damage: `[166,180,171,167]` → `[166,179,171,167]`, `instrumentDic` still 807, plus one long note with a broken end time |
| zero 16 bytes at offset **55984** (final block) | **`Loading failed: An unknown error occured. Please try again. ErrCode: NIQQ0`** popup → returns to main menu |

The mid-file corruption loading fine **rules out any trailing checksum/MAC over the plaintext**. The tail-only failure therefore comes from **block-cipher padding validation** — the decrypt throws before the parser runs. Conclusions:

* It is a **block cipher in CBC mode**, **not** a stream cipher.
* Padding is **PKCS7** (the game reports a clean decrypt failure, not a parse error — i.e. a **padding oracle**).
* Block size is **16 bytes** (the rejected region is exactly the last 16).
* Therefore a correct key yields the **raw, structured chart bytes** — no extra transform layer. This is why printability/magic oracles were always doomed, and why the **padding oracle is the right test**: it is content-independent and works for binary plaintext.

**Key sweep with the padding oracle (content-independent) — all negative:** 26,931 keys (the full 15,722-entry `a` string table in ASCII and base64 forms, every byte-window of every static `Byte[]`, all 512 static strings, plus MD5/SHA1/SHA256 derivations) → 98 padding-valid candidates, matching the ~105 expected by chance (1/256) → full-decrypt verification of all 98 (URL-hash + entropy/zero-fraction) → **0 hits**. Earlier sweeps add `rjn`/`bundleCryptKey` windows, the `a.rn*` table and `svk`–`svr`. **The key is not recoverable from the binary's static constants.**

**Practical limit of the oracle:** the padding oracle underwrites the classic CBC plaintext-recovery attack, but at **one crafted body per query** (~2,000 queries per 16-byte block, ~3,500 blocks) that is millions of song loads — not viable. The MITM route cannot recover the whole chart.

**Remaining realistic routes:** (a) locate the S-box's owning class to read the bespoke AES `Decrypt` directly; (b) a single cold-function hook / hardware breakpoint to name the decrypt; (c) reconstruct per song (proven); (d) archive as served.

### The cipher is managed BCL Rijndael — S-box LOCATED (2026-09-18)

Scanning all readable memory for the 256-byte AES S-box and resolving each hit's object header (validated: `object[0] == class.handle` ✓) shows the S-box belongs to **`mscorlib/RijndaelManagedTransform.s_Sbox`**, alongside `s_T`, `s_TF`, `s_iT`, `s_iTF` (`Int32[1024]`). **There is no bespoke AES.** The chart cipher is therefore the *managed Mono* `RijndaelManagedTransform` — reached virtually through `ICryptoTransform`, which is exactly why no direct call site was ever resolvable.

### `bbk` — the game's own cipher (hardcoded AES-256 key+IV)

Found by enumerating classes declaring a static `System.Byte[]`. **`Assembly-CSharp/bbk`** (11 methods):

| field | value |
|---|---|
| `wdp` (static `Byte[32]`) | `ce2e2185e0cde39d3ef798e1678b950e7ac9f7014307a04aed8c4faabe3e58f0` |
| `wdq` (static `Byte[16]`) | `a5cf61a270f467ca7611cfae8bd364a5` |
| `wdr` (static `String`) | `zi4hheDN450+95jhZ4uVDnrJ9wFDB6BK7YxPqr4+WPA=` = base64(`wdp`) |
| `wds` (static `String`) | `pc9honD0Z8p2Ec+ui9NkpQ==` = base64(`wdq`) |

Nine methods are `String->String` (`gpe`, `gvb`, `gvc`, `nuc`, `fki`, `mum`, `cwx`, `nc`, `nrf`); `fxr()` and `gva()` are `Void` static initialisers (`fxr()` aborts, `gva()` works). **`wdp`/`wdq` do not decrypt the chart.** Its methods call *hash* factories (`MD5.Create` / `SHA1.Create` / `SHA256.Create`) and they are **not** in the `RijndaelManaged..ctor` call-site list — so `bbk` is a **custom hash-based string cipher**, and it is the *only* game class that constructs a symmetric/hash cipher at all.

**Methodology:** static field values read as `ERR`/null until the class is initialised; calling a static 0-arg method forces it.

### Complete crypto-construction inventory — and what it implies

Call-site scan for every `RijndaelManaged..ctor` / `Rijndael..ctor` / `AesManaged..ctor` / `AesCryptoServiceProvider..ctor` / `CryptoConfig.CreateFromName` / `CreateDecryptor` / `CreateEncryptor`, plus `Aes.Create` / `SymmetricAlgorithm.Create` factories, resolves to only these game methods:

`da.AESDecrypt`, `da.AESEncrypt` · `qe.cal`, `qe.fal`, `qe.fam`, `qe.gvf`, `qe.jqv` · `zf.AESDecrypt`, `zf.AESEncrypt` · `InGameCore.dcg` · `ZipAESTransform..ctor` · `AesManaged..ctor` · `CryptoConfig.CreateFromName` · `Aes.Create` · `SymmetricAlgorithm.Create` · `bbk.*` (hash factories only).

**None of them is the chart decrypt.** Combined with the S-box being the BCL's, this means the chart cipher's construction happens in code that **a scan cannot currently see** — and the known cause is that **AOT code is decrypted lazily per method**: a scan misses any method that has not yet executed in that process. The practical consequence is important:

> **Re-run the construction-site scan *after* a chart has been loaded in the same process.** The earlier scans may have been performed in a process where the chart path had not run, so the chart-decrypt method's code was still encrypted.

### API decrypted — music list recovered (2026-09-18)

`_cdn_rewrite.py` captures API bodies too; they decrypt with the **live** `zf.aes_key`/`zf.aes_iv` read from the running game. Captured: `c2s_login` (member: `MEMBER_ID REDACTED_MEMBERID`, `NICKNAME REDACTED_NICK`, `STEAM_ID REDACTED_STEAMID`), `c2s_get_myinfo`, and `c2s_get_gameinfo` — the **full 1,201-song music list** with `CRYPT_KEY`, `VERSION`, `GAME_MODE`, `LEVEL`, `NOTE`, `TEMPO`, `GAUGE_RATE`, `JUDGEMENT_TIME`.

Findings:
* **`CRYPT_KEY` is unique per song** (1,201 distinct values across 1,201 songs), so it cannot be the shared chart cipher key.
* `VERSION` is uniform (22) across all songs.
* `GAME_MODE` varies (MilK/Conflict = 2, another MilK entry = 1) — a candidate explanation for the shared 16-byte prefix.
* **The member DTO contains no `AES_KEY`/`AES_IV`**, so `vx.AES_KEY`/`AES_IV` are client-side, not server-delivered.
* Body framing: the response body is base64 whose decode is 1 byte short of a 16-byte boundary — i.e. a 1-byte prefix precedes the base64 payload.

### ⚠️ The module base CHANGES per launch — rebuild symbol maps every session

Observed bases: `0x6ffff23c0000`, then `0x6ffff2340000` (an `0x80000` shift). Every `Il2Cpp.Method.virtualAddress` equals `base + RVA`, so **a symbol map built in one session is off by the delta in another** — and a call-site scan whose targets came from a stale map will scan for the wrong addresses and return garbage. **Always query the module base and method VAs in the same run as the call-site scan.** (The code is also relocated between launches, which is consistent with the protector's lazy per-method decryption.)

### `bbk` resolved — `Aes.Create()` + `Convert.FromBase64String`

Disassembling `bbk.gva` and `bbk.nrf` (with the session-fresh name map) shows they call **`mscorlib.Aes.Create/0`**, and `bbk.nrf` additionally calls **`mscorlib.Convert.FromBase64String/1`**. So `bbk` is a **base64-in → AES → base64-out string cipher**, and it is the **only** game code that reaches a symmetric cipher through the `Aes.Create` factory. Its key/IV (`wdp` 32 B, `wdq` 16 B) still do **not** decrypt the chart under AES CBC/ECB/CFB/OFB.

**Outstanding puzzle (as of 2026-09-18):** runtime evidence proves the chart is **CBC+PKCS7**, yet a full call-site scan for every symmetric-cipher construction (`RijndaelManaged..ctor`, `Rijndael..ctor`, `AesManaged..ctor`, `AesCryptoServiceProvider..ctor`, `CryptoConfig.CreateFromName`, `CreateDecryptor`/`CreateEncryptor`, plus the `Aes.Create`/`SymmetricAlgorithm.Create`/`Rijndael.Create`/`DES.Create`/`RC2.Create`/`MD5.Create`/`SHA1.Create`/`SHA256.Create` factories) resolves to only 29 enclosing methods — `da.AESDecrypt/Encrypt`, `qe.cal/fal/fam/gvf/jqv`, `zf.AESDecrypt/Encrypt`, `InGameCore.dcg`, `DeflaterOutputStream.InitializePassword`, `ZipAESTransform..ctor`, `bbk.*`, and BCL-internal (`Aes.Create`, `Aes..ctor`, `DES…`, `RC2…`, `CryptoConfig.CreateFromName`, `RijndaelManaged.*`, `AesManaged..ctor`, `AesCryptoServiceProvider.*`). **No chart decryptor.** A same-process re-scan *after* a chart load produced the same 29 — so lazy code decryption does not explain the gap. The remaining explanations are: the decrypt is `bbk` with a key not yet extracted, or it reaches the cipher through a path these scans cannot resolve.

### `bbk` cracked — and the string table is a HASH table (2026-09-18)

**`bbk` is a base64↔base64 AES string cipher.** Calling all 11 methods:

| role | methods | behaviour |
|---|---|---|
| **encrypt** | `gpe`, `fki`, `mum`, `gvb` | all four return **byte-identical** output for a given input → they share one key/scheme |
| **decrypt** | `nrf`, `cwx`, `nuc`, `nc`, `gvc` | abort on non-ciphertext (padding failure) |

Semantics established exactly by length arithmetic: `bbk.gpe(<74,668-char ASCII>)` returned **99,564 chars** = base64(74,672) = base64(ceil((74,668+1)/16)·16). So it **encrypts the string's UTF-8 bytes** with AES-CBC/PKCS7 — it does **not** base64-decode its input first. Hence:
* encrypt = `base64(AES-CBC(PKCS7(utf8(text))))`
* decrypt = `utf8(AES-CBC-decrypt(base64_decode(text)))`
* `bbk.nrf` additionally calls `Convert.FromBase64String` ✓

Its key/IV (`wdp`/`wdq`) still do **not** decrypt the chart, and all five decryptors abort on the chart — so `bbk` is the game's **string** cipher, not the chart's.

**⚠️ MAJOR CORRECTION: the `a` string table is a SHA-256 table, not encrypted strings.** All **10,986** of its base64 values decode to **exactly 32 bytes**, and none decrypt to readable text under AES with any known key. They are **hashes**. This invalidates several earlier sweeps that treated those 11k values as key material — they were hashes all along.

**Metadata literal sweep (new):** 17,384 printable runs in `global-metadata.dat` → 517 key candidates → 5 padding-valid, all `pad=0x01` ≈ chance → **false positives**.

**`CRYPT_KEY` derivation sweep (new):** 325 candidates built from MilK's `rjn` and its `CRYPT_KEY` (concatenate/reverse/xor + MD5/SHA1/SHA256/SHA512, add/sub/xor/rotate/permute by the `{1,2,3}` sequence, both key ends) → 7 padding-valid ≈ chance, all confirmed false positives by full decrypt.

**Song identity resolved:** MilK 4K SHD = **`MUSIC_ID 1603`, `GAME_MODE 2`** (the `A2` mode, matching `da.rou = "LIVE A2"`), `CRYPT_KEY = 3,3,1,2,2,3,1,2,2,2,2,1,3,2,2,1`, and the music list's `NOTE` field confirms **1136 total notes = 684 `normalNoteData` + long notes** ✓.

### EZ2AC format lineage — and the `final_url_ez`/`final_url_ezi` naming is CORRECT (2026-09-18)

Reference: **`github.com/freem/ez2stuff`** (EZ2DJ/EZ2AC tooling; C sources kept locally in `reference/ez2stuff/`, git-ignored). Its `formats.md` documents the arcade formats, and they explain EZ2ON's naming:

* **`.ez` = the note chart**, magic **`EZFF`** (`45 5A 46 46`), then: `0x04` null, `0x05` version, `0x06`–`0x45` internal track name (64 B), `0x86` ticks/measure, **`0x88` initial BPM (float)**, `0x8C` track count, `0x8E` total ticks, `0x92` “other” BPM. Track data follows as `EZTR` blocks.
* **`.ezi` = the keysound index and it is TEXT**: `[index] [velocity] [filename]` per line, velocity only ever 0 or 1 — e.g. `1 0 filename.wav`. (Matches what this project had already noted as `<id> <flag> <filename>` with flag 0/1.) Old format uses note names (`C#0`), new format a numeric index (max 2048 sounds).

> **⚠️ CORRECTION:** the earlier note “the `final_url_ez` / `final_url_ezi` mapping is INVERTED” is **wrong** — the API's naming agrees with EZ2AC: `final_url_ez` **is** the chart and `final_url_ezi` **is** the keysound index. (What was inverted were *my* own labels.) The runtime evidence — corrupting the 56,000 B object broke a long note in the chart — is consistent with this, not against it.

**Strong corroboration from sizes:** MilK's `.ezi` ciphertext is **18,192 B** and the game reports **807 keysounds**. 18,192 ÷ 807 ≈ **22.5 bytes per line** — exactly the width of a text line like `123 0 01-Drums_1_Crash_001.flac`. So the `.ezi` plaintext is **uncompressed text of essentially the same length as the ciphertext**.

**Arcade `.ez` encoding — tested, negative.** From EZ2DJ 7th Trax v1.5 onward the arcade `.ez` is encoded: **subtract a repeating 512-byte static keystream, then reverse the whole file** (`ezdec_715.c`, `ezdec_720.c`). Both 512-byte tables were applied to the EZ2ON payloads in all three combination modes (subtract / add / xor × forward / reversed) → **no `EZFF`, no `PK`, no text**. EZ2ON does not use the arcade keystream.

**Two-time-pad test — negative, and informative.** A *static* keystream would make MilK vs Conflict a two-time pad, and since both `.ezi` plaintexts are **ASCII text**, the difference would stay low-entropy. It does not: `ct₁−ct₂` and `ct₁⊕ct₂` both give entropy `≈7.96`, zero-fraction `0.47 %`, printable fraction `≈45 %` — i.e. **random**, except for the **first 16 bytes, which are exactly zero**. So there is **no static keystream**; the key is per-song, and bytes `0x00–0x0F` are a **16-byte constant header** (identical for two different 4K SHD songs, which a keyed cipher could not produce) with the ciphertext proper beginning after it.

### ⚠️ Live-Memory Trapping: Why Guard Pages Crushed the Game

`MemoryAccessMonitor` works by `mprotect(PROT_NONE)` + a SIGSEGV handler, and it is **one-shot per page**. `da`’s static-fields page (`0x64f72000`) is read **~350×/second** by per-frame code (`0x6ffff2db4c89` ×348, `0x6ffff2dbeee3` ×52 in seconds) from several threads. Hence:

* **Without re-arming** the first stray access consumes the guard and `da.rus` is installed **untrapped** (observed: 403 events, **0** on the slot).
* **With re-arming** every one of those accesses becomes a trap; each re-enters Frida’s handler, calls back into JS and re-`mprotect`s. Unity’s main thread plus IL2CPP worker/GC/audio threads then fault **concurrently while the handler is mid-flight** → broken unwinding → crash. The game has no recovery path for a failing static-field read.

**Rule: never guard a shared/hot page.** If live watching is needed, use either **hardware breakpoints** (`DR0–DR3`, watch a single *address*, no `mprotect`, ~2–3 traps per song load — the correct tool) or an **`Interceptor.attach` on a cold, once-per-song function**. Do not re-arm page guards.

### Static Call-Graph Symbolication (2026-09-17)

Because the AOT code is readable, calls can be resolved to managed method names:

* **`_sym.js`** enumerates **all 176,021 methods** across all 97 assemblies and returns `virtualAddress -> "Class.method"` for a supplied address list (~8 s).
* **`_findcallers.js`** scans the whole readable code region (RVA `0x1000`–`0x48f4000`, ~76 MB) for `E8 rel32` call sites targeting given addresses (~100 s). **Gotcha**: RPC string args must be `parseInt(t,16)`-ed before being used as object keys, and the concatenated `*_run.js` must be regenerated after editing the driver.
* **`_encl.js`** maps a call site to its enclosing method (largest method VA ≤ site). Outputs: `_sym_all.json`, `_callers.json`, `_encl.json`.

**Crypto-method inventory** (resolved call targets):

| Method | Role |
|---|---|
| `da.AESDecrypt` / `da.AESEncrypt` (String→String, static) | AES-256-CBC w/ `da.aes_key`/`da.aes_iv`; used only by `LOAD_COURSE_RECORD`, `LOAD_FAVORITE`, `LOAD_LOCAL_DATA` (local save files) |
| `zf.AESDecrypt` / `zf.AESEncrypt` | API / TCP session layer (`zf.aes_key`/`zf.aes_iv`) |
| `qe.cal` / `qe.fal` / `qe.fam` / `qe.gvf` / `qe.jqv` | **Rewired**, not chart crypto — see the red-herring note below |
| `bbk.*` | ditto (Rewired / user-data store) |
| `qe.fan` / `qe.fao` / `qe.kha` / `qe.lrw` | **Rewired** `UserDataStore_File`: Zip create/extract + `CLZF2` compress (their `bcg`/`bcf`/`bch` callees are nested in `UserDataStore_File` and `bch` holds a `Rewired.Utils.Libraries.CLZF2.CLZF2` field) |
| `qe.fah` / `qe.faf` | 96-byte (128-char b64) random key-blob wrap / unwrap — Rewired data obfuscation |
| `da.chn` / `da.cin` / `da.cik` / `da.cqo` | **`Int32->String` string-table getters**, not crypto (verified by signature dump) |
| `da.rus` | `da.co` at **static offset 840 (0x348)**, `staticFieldsData` = `0x64f72a80` → slot `0x64f72dc8` |

> **Red herring cleared (2026-09-18):** an earlier version of this table labelled `qe.cal/fal/fam/gvf/jqv` and `qe.fan/fao/kha/lrw` as chart-crypto candidates. Dumping the enclosing class shows `bcg`/`bcf`/`bch` are nested in **`UserDataStore_File`** and `bch` carries a `CLZF2` field — this is **Rewired** input-config persistence (zip + AES), unrelated to chart delivery.

**Key-material table `a.rna`…`a.rnz` + `a.rov`** (26 static `()->String` getters, 44-char base64 = **32 raw bytes each**, no wrapping): `rnn` = `1PP1YL+n+jJVUqKo1JyP/X1c21SxuHg4WHVDP3u/Ic0=`, `rov` = `NBT8ywEUvpZtB5LHyUfX3AY830rph/1drfjlnxoQlpc=`, … None of them (alone, or as 16/24/32-byte keys, in any key/IV pairing, CBC/ECB/CFB/OFB) decrypts the CDN `.ezi`.

**Disk artefacts**: `EZ2ON REBOOT R/1PP1YL+n+jJVUqKo1JyP/X1c21SxuHg4WHVDP3u/Ic0=` is an **empty directory tree** created because some code used the base64 string `a.rnn` as a *file path*. `EZ2ON REBOOT R/Replay/*.ezr` are plaintext replay files (45–100 KB) matching `da.RecordData` (which holds score/judgement/note-tick lists, **not** the chart).

---

## 3. Extraction & Dumper Tools

> **⚠️ Path note (2026-09-18 repository tidy-up).** Every investigation script that used to sit in the repository root now lives under **`tools/`** — see **`tools/README.md`** for the full layout, the `build_run.sh` step, and the “things that crash the game” list. The user-facing ripper scripts below (`extract_assets.py`, `find_bundle.py`, `decrypt_all.py`, `harvest_chart.py`, `harvest_key.py`, `run_dumper.sh`) remain at the root.
>
> | moved to | what |
> |---|---|
> | `tools/il2cpp/` | `_il2cpp_bridge.js` + all IL2CPP drivers (`_sym`, `_encl`, `_findcallers`, `_dump_code`, `_igc`, `_tables`, `_cova`, `_namemap`, `_klassname`, `_staticscan`, `_finddisp`, `_sbox3`, `_asascan`, `_diag.py`, `_poll_capture.py`, …) |
> | `tools/probes/` | passive probes **and** the hook experiments that crashed the game |
> | `tools/mitm/` | `_cdn_rewrite.py`, flow parsing, API decryption |
> | `tools/crypto/` | `_rijndael256.py`, `_rijsearch.py`, key sweeps, brute-forcers |
> | `tools/legacy/` | superseded first-generation tooling |
> | `data/` | derived analysis artefacts (JSON symbol maps, key tables, scan results) |
> | `logs/` | captured run logs |
>
> Runnable drivers are the generated **`*_run.js`** files (bridge + driver); regenerate them with `bash tools/il2cpp/build_run.sh` after editing any driver. `_run.js` files are git-ignored.

* **`dump_song.py`** (**recommended capture tool**, repository root): watches `InGameCore.instance` and on each new chart (a) downloads the signed CDN URLs *immediately* (they expire in ~150 s) and (b) snapshots the in-memory state. Writes, per song, into `extracted_charts/<musicresourcename>_<keymode>_<levelmode>_<gamemode>/`: `ident.json`, `cdn_ez_*.bin` / `cdn_ezi_*.bin` (payloads byte-exact **as served**, still encrypted), `mem_rjl.bin` / `mem_rjm.bin` / `mem_rjn.bin` (the buffers + key the game holds in `da.rus`), and `instrumentDic.json` (the decrypted keysound index). Driver: `tools/il2cpp/_dumpsong.js`. Read-only, low-rate polling, **no hooks** — safe.
* **`harvest_chart.py`**:
  * Zero-hook live memory harvester that connects to Frida Gadget (`127.0.0.1:27042`).
  * Monitors `InGameCore.instance` to automatically capture `ezi_url` and `ez_url`, downloading `.ezi` charts and `.ez` keysound maps on song selection.
  * Fallback mode scans heap memory for `EZFF` headers to dump charts directly from RAM.
  * NOTE: bundled `download_file()` uses a generic UA and currently 403s; the proven download path is the host-side curl fetch in `fetch_chart.sh` (see below).
* **`fetch_chart.sh`** (host-side CDN fetch, not yet wired into `harvest_chart.py`):
  * Captures a fresh `ezi_url`/`ez_url` via Frida, then immediately `curl`s them with the game's exact request headers (from `mitmproxy`), saving to `extracted_charts/_inproc/`.
  * Requires the game running with a fresh, unexpired URL in memory (replay/pause a song, then run).
  * Achieved HTTP 200 for both files; the downloaded bytes are the CDN's **encrypted** form (see “Chart Payload Cryptanalysis”).
* **`extract_assets.py`**:
  * Standalone tool to extract raw audio assets (FLAC, OGG, WAV) and BGA video (`.mp4`) files.
  * Usage: `python3 extract_assets.py rebind` (audio) or `python3 extract_assets.py rebind --bga` (audio + BGA video).
* **`find_bundle.py`**:
  * Standalone tool to inspect container asset paths and map encrypted bundle hashes to song codenames, distinguishing between `AUDIO` (Pack 01) and `VIDEO` (Pack 02) asset types.
  * Supports indexing all 1,231 bundles into `song_index.json`, keyword searching, and on-demand decryption (`--decrypt`).
* **`decrypt_all.py`**:
  * Offline Python script using `true_key_1024.bin` to decrypt bundles.
  * Supports `--limit N` (default: 5) or specific file arguments to optimize disk usage.
* **`_diag.py` / `_diag.js`** (live introspection, read-only):
  * Enumerates `InGameCore` fields via IL2CPP exports, correctly separating **static** (read with `il2cpp_field_static_get_value`) from instance fields; dumps strings/byte[]/int/bool plus a heap scan for the `EZFF` magic.
  * Key findings: `bundleCryptKey` (`System.Byte[]` @ `0x830`) and the static `svk`–`svr` AES key/IV material.
* **`_poll_capture.py` / `_poll.js`** (live capture, read-only):
  * High-frequency poller: reports `InGameCore` state, catches a transient `bundleCryptKey`, detects new `ez_url`/`ezi_url` and immediately `curl`s them (with the game's exact headers), and periodically heap-scans for in-memory decrypted `EZFF` (dumps 256 KB).
  * NOTE: the URL must still be within its ~150 s TTL — expired URLs return a 110-byte CloudFront `AccessDenied` XML.
* **`_decrypt_test.py`**:
  * Brute-forces AES (CBC/CFB/OFB/CTR/ECB × 16/24/32-byte keys × candidate IVs) against captured `.ezi`/`.ez` ciphertext, flagging `EZFF` magic or high-ASCII plaintext.
* **`_parse_mitm.py`**, **`_dump_pattern.py`**, **`_dump_api.py`** (mitmproxy addons):
  * Parse a saved flow file offline (`flow_dumps`) → `c2s_get_pattern_file` request/response pairs (`mitm_parsed/pattern_*.json`), API response bodies (`mitm_parsed/c2s_*.bin`), and every CDN ciphertext (`mitm_parsed/cdn_*.bin`).
* **`_decrypt_api.py`** / **`_decrypt_api_all.py`**:
  * Decrypt API responses with the session key (AES-CBC, ASCII key/IV) → `mitm_parsed/pattern_keys.json` and the full music list.
* **`_staticscan.js`** (the key one): IL2CPP reaches static fields via `mov reg,[reg2+0xb8]` (static-fields base) **followed by `add reg, imm32`** — *not* a memory displacement. Grading the *load* displacement form misses every real static access (that mistake made the first scan return 901 mostly-BCL hits). Searching for `48 8B <modrm mod=10> B8 00 00 00` then `add r64, imm32` within 32 bytes cuts `da.rus` (offset 0x348) down to **10 sites / 5 locations**. A store to a static reference field is followed by `call 0x6ffff26d2800` (GC write barrier).
* **`_encl.js` caveat**: enclosing-method attribution picks the largest method VA ≤ site, so it reports nonsense for sites far into a method (`ft.MoveNext off 0x2d042`). Use it only as a hint; the disassembly is authoritative.
* **Lazy code decryption**: parts of the module are still high-entropy and become readable only after the corresponding methods run — so a scan of the code region can **miss** sites until the game has exercised that path.
* **`_il2cpp_bridge.js`** + drivers (`_bridge_*.js`, `_rvinvoke.js`, `_dump_code.js`, `_codedump.js`): vendored `frida-il2cpp-bridge@0.14.0` plus RPC drivers. `onMain()` runs managed calls on the game's main thread (required for BCL AES under Wine). `_dump_code.js` writes 4 KB method body dumps to `il2cpp_code/`.
* **`_watch.js` / `_watch.py` — ⚠️ CRASHED THE GAME (do not repeat)**: `MemoryAccessMonitor` guard pages **do** fire under Wine/Proton (verified: real instruction-level events captured, and `Memory.protect(..., '---')` correctly makes reads fault), but **trapping the game's own memory accesses is destructive**. The 10 ms `Il2Cpp.perform` polling loop is a second likely culprit.
* **`_slotwatch.js` / `_slotwatch2.js` — ⚠️ ALSO CRASHED THE GAME (definitive)**: guarding **only** the `da` static-fields page (`0x64f72000`, holding the `da.rus` slot `0x64f72dc8`) is unusable:
  * `MemoryAccessMonitor` **fires only once per page** and then stops trapping it. The very first (noise) fault consumes the guard, so `da.rus` was installed at `0x131f2b060` **completely untrapped** (run 1).
  * Re-arming the page after every fault (run 2) turns per-frame noise into a fault storm: **403 events in seconds, 0 of them on `da.rus`**, then crash. The hot readers are `0x6ffff2db4c89` (×348) and `0x6ffff2dbeee3` (×52), both reading the `da` static **offset 0x178 (376)**.
  * **Conclusion: `da`'s static-fields page cannot be instrumented by guard pages.** If a live trap is ever retried, arm it only for a **narrow time window** (e.g. right after `InGameCore.ezi_url` becomes non-empty), never continuously, and never on a page touched per-frame.
* **Observed `da` static-slot reads** (offsets relative to `staticFieldsData`): `376` (0x178) — hot, per-frame, `0x6ffff2db4c89`/`0x6ffff2dbeee3`; `656` (0x290); `713` (0x2c9); `856` (0x358) from `0x6ffff2b0dd19`. Note 856 = `da.rus` (840) + 16 but the instruction there is `mov [rsp+8], rcx` (a stack write), so 856 is almost certainly a **stack** address, not a `da` field — that earlier lead was a false positive.
* **`_find_aes.js`** / **`_probe_aes.js`**:
  * Locate the AES implementation by its 256-byte static S-box; enumerate `AesTransform` methods + native pointers.
* **`_hook_aes2.js`** (safe) / **`_hook_aes.js`** (UNSAFE — crashed the game):
  * `Interceptor.attach` on `AesTransform..ctor` to capture the live key/IV. `_hook_aes2.js` validates every pointer with `Process.findRangeByAddress` before reading; `_hook_aes.js` did **not** and must not be reused.
* **`_find_vy.js`** / **`_find_vx.js`** / **`_find_refs.js`** / **`_find_wy.js`**:
  * IL2CPP reflection helpers for the `vy`/`vx` member DTO, the `wy` pattern DTO, and all fields referencing a given type.
* **`run_dumper.sh`**:
  * Runs `Il2CppDumper` via `.NET 10` roll-forward runtime into `il2cpp_out/`.
  * Expects `EZ2ON REBOOT R/EZ2ON_Data/il2cpp_data/Metadata/global-metadata_decrypted.dat` (currently **absent**). It fails on the on-disk metadata because `0xFAB11BAF` is missing (see §2 “Metadata Obfuscation”).

### Cipher-analysis tooling (2026-09-18)

* **`_rijndael256.py` / `_rijsearch.py`** — parameterised Rijndael (any Nb/Nk) plus the `make_dec(key, Nb)` block-decrypt factory. **Verified**: the Nb=4 path reproduces the FIPS-197 vector `69c4e0d8…`. Use this instead of `pycryptodome` for any 256-bit-block work (pycryptodome cannot do it).
* **`_staticscan.js`** — the key static-field scanner: finds `mov r64,[r64+0xb8]` immediately followed (within N bytes) by `add r64, imm32 == offset`. **This is the correct signature for IL2CPP static-field access**; scanning for the *displacement* form instead yields ~90× more false positives. A static reference-field **store** is followed by `call 0x6ffff26d2800` (GC write barrier).
* **`_finddisp.js`** — scans for `mov reg,[reg+disp32]` (instance fields). Used for `bundleCryptKey` (0x830), `instrumentDic` (0x550), `normalNoteData` (0x510).
* **`_sbox.js`** — scans rw- memory for the AES forward/inverse S-box (`klass_of` reads the candidate object header at −0x20).
* **`_klassname.js`** — maps a raw `Il2CppClass*` back to `Assembly/Namespace.Class` by scanning all class handles.
* **`_hookcrypto.js` — ⚠️ CRASHED THE GAME (2026-09-18).** `Interceptor.attach` on the cipher *construction* functions (`RijndaelManaged..ctor`, `Rijndael..ctor`, `RijndaelManagedTransform..ctor/7`, `RijndaelManaged.CreateDecryptor/2`, `AesManaged..ctor`, `AesCryptoServiceProvider..ctor`, `Aes.Create/0`) killed the process immediately — no gadget port, no Wine processes afterwards. These were expected to be *cold* (once per cipher), so the crash is not about call frequency. **Conclusion: `Interceptor.attach` is not viable on this target, period — it has now crashed the game three times (hot BCL function, guard pages, cipher ctors).** Any future live work should use read-only means only (memory reads, managed invocation via the bridge), or an out-of-process debugger.
* **`_probe2.js` / `_probe_watch.py`** — zero-risk active probe: builds a synthetic `da.co` whose three `byte[]`s are filled with a 16-byte marker, writes it into the `da.rus` slot, then tracks the slot value and counts marker occurrences in rw- memory. Used to prove `da.rus` is not on the chart path. Safe because it only writes a field the game is not currently using.
* **`_igc.js`** — dumps `InGameCore` instance field offsets (the authoritative source for `bundleCryptKey` 0x830, `instrumentDic` 0x550, etc.).
* **`_asascan.js`** — raw rw-/r-- memory scan for ASCII byte patterns + an `ctx()` helper to render surroundings.
* **`_findbbl*.js`** — scan rw- memory for a class pointer to locate live DTO instances. **Note**: constructing the needle from the pointer *value* (not the memory *at* it) is essential; class-table hits are frequent false positives.
* **`_dcg.js`** — 3-arg `(byte[],byte[],byte[])` main-thread invoker used to probe `InGameCore.dcg`.
* **`_poll_da.js` / `_poll_da.py`** — **safe** passive watcher (4 Hz read of the `da.rus` slot, no guard pages, no in-process loop) that dumps `rjl`/`rjm`/`rjn` whenever they change. This is the pattern to copy for any future live observation.

---

## 4. Output Directories

* `extracted_charts/<song_id>/`: Output destination for `.ezi` chart files and `.ez` keysound maps.
* `extracted_assets/<song_id>/`: Output destination for extracted FLAC/OGG audio files and BGA `.mp4` video files.
* `EZ2ON REBOOT R/decrypted_bundles/`: Output destination for decrypted `.unity3d` bundle containers.
* `true_key_1024.bin`: 1,024-byte master XOR decryption key.
* `song_index.json`: Mapped index of bundle hashes to song IDs/codenames (audio and video).
* `il2cpp_out/`: Extracted C# class representations and symbol mappings (pending a decrypted metadata dump).

---

## 5. Current Blockers & Next Steps

**Blockers**
* **CDN chart decryption (main blocker)**: the payload is **confirmed encrypted** and **not integrity-checked**, but the transform has not been located. ~2.7M candidate decryptions tested against six independent oracles → **0 hits** (see §2 “Cipher search status — exhaustive negatives”).
* **The chart and index are named inversely** by the API: `final_url_ez` = the **chart** (56,000 B for MilK), `final_url_ezi` = the **keysound index** (18,192 B). Verified by corrupting each and watching the parse.
* **No BCL crypto in the chart path.** A complete scan of `RijndaelManaged..ctor`/`AesCryptoServiceProvider..ctor` call sites yields only 12, all accounted for (local saves, Rewired, API/TCP, SharpZipLib, the inert `dcg`, factories, and **`bbk`** — a game *string* cipher with a hardcoded AES-256 key/IV). Crypto is invoked **virtually**, so call-site scanning cannot see `CreateDecryptor`/`TransformFinalBlock`; and the S-box exists only as `global-metadata.dat` field-initialiser blobs, implying a **bespoke managed AES** whose call sites static analysis cannot reach.
* **Live trapping is dangerous here.** `MemoryAccessMonitor` guard pages on `da`'s static-fields page crash the game (hot, multi-threaded, one-shot guard — §2). Hardware breakpoints or a single cold-function hook are the correct tools.
* No plaintext chart has been recovered from RAM. Scans for `EZFF`, `PK\x03\x04` and ASCII keysound names found nothing → the decrypted buffer is transient, and/or the chart plaintext does not use the EZ2AC `EZFF` magic.

**Solved / superseded**
* ~~API JSON / `bundleCryptKey` unavailable~~ → **API session cipher cracked**; `bundleCryptKey` = base64-decoded into `da.rus.rjn` (confirmed against a live API response).
* ~~`bundleCryptKey` is per-session~~ → it is **per-song**.
* ~~The payload might be a plaintext native container~~ → **rejected** (XOR of two different 4K SHD charts is random).
* ~~Compression ruled out~~ → that earlier test was on the **raw ciphertext** and was meaningless; the correct test (decrypt *then* decompress) is now covered and also negative.
* ~~The URL path hash identifies the plaintext~~ → hash/entropy/printability all negative across the full key sweep; unconfirmed.
* ~~`qe.*` are the chart crypto~~ → **Rewired** `UserDataStore_File`; and `bbk.*` (which I had also mis-filed there) is the game's **string** cipher.
* ~~`da.chn`/`da.cin` are decryptors~~ → `Int32->String` string-table getters.
* ~~`da.rus` is the chart source~~ → it is a transport/audit record, wiped at song end; the game runs fine with garbage in it.
* ~~`MemoryAccessMonitor` guard pages~~ → **crash the game**; do not repeat.
* ~~Method bodies unreadable~~ → AOT code is decrypted in memory (lazily per method).
* ~~All managed calls crash~~ → Wine/CNG thread affinity; `onMain()` fixes it.

**Next Steps**
1. **`Interceptor.attach` on `Aes.Create/0`** (cold — called only a handful of times per launch, versus the hot BCL function that crashed things before) to log `Thread.backtrace()` when a cipher is constructed during a chart load. This directly resolves the outstanding puzzle: no game code appears to create the chart cipher, yet the chart is provably CBC+PKCS7. A backtrace names the real call site. **Moderate risk (code-modifying hook) — ask the user first.**
2. **Hardware breakpoint variant** of (1): `DR0` on `Aes.Create/0`, catching `#DB` via `Process.setExceptionHandler` — no trampoline, safer.
3. Continue extracting `bbk`'s per-method key material (its encrypt methods are callable oracles; `bbk.gpe` output length is a known transformation of input length).
4. Fallback (proven twice): reconstruct per song — index from `InGameCore.instrumentDic` (0x550), chart from the parsed note structures (`normalNoteData` 0x510 / `longNoteData` 0x520 / `bpmNoteData` 0x540 / `MeasureScaleData` 0x5C0).
5. Archive-as-served: `fetch_chart.sh` captures every CDN chart byte-exactly.
