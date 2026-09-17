# EZ2ON REBOOT: R - Reverse Engineering & Asset Ripper Suite

A set of specialized tools for reverse engineering, decrypting, and extracting game assets (FLAC audio keysounds, BGA video files) from **EZ2ON REBOOT: R**.

> **Note**: This toolset is provided strictly for **archiving and personal educational purposes only**.

---

## Technical Overview

* **Game**: EZ2ON REBOOT: R (Unity IL2CPP 64-bit Windows executable running under Proton / Wine).
* **Bundle Encryption**: The first **1,024 bytes (0x400 block)** of each `.unity3d` bundle in `Packs/01` (Audio) and `Packs/02` (Video BGA) are encrypted using a static XOR keystream (`true_key_1024.bin`). Offsets `0x400` onwards contain unencrypted Unity asset structures.
* **TextAsset & VideoClip Extraction**:
  * Audio keysounds (FLAC/OGG) stored as `.bytes` in `TextAsset` objects are extracted directly from raw C++ binary object streams to prevent UTF-8 string encoding corruption.
  * BGA videos (`.mp4`) in `VideoClip` objects are extracted cleanly by parsing `m_ExternalResources` stream offsets into 720p H.264 MP4 videos.

* **Chart Delivery & API Encryption**: Charts are **not** bundled in the client; they are fetched on demand from a CloudFront CDN (`game1-cdn.ez2game.co.kr`) and are **encrypted (not compressed)** on the wire. The game decrypts them locally after download.
  * **API session cipher — CRACKED (2026-09-16)**: the `game1-play.ez2game.co.kr` HTTPS API is **AES-CBC/PKCS7** with **key = the 32 ASCII bytes of `zf.aes_key`** and **IV = the 16 ASCII bytes of `zf.aes_iv`** (runtime, session-scoped). This decrypts `c2s_login`, `c2s_get_myinfo`, `c2s_get_gameinfo` (1,201-song music list) and `c2s_get_pattern_file` (→ `bundleCryptKey`). See `AGENTS.md` §2 “API Session Cipher — CRACKED”.
  * **`bundleCryptKey` is per-session, not per-song** (identical across all songs/difficulties in a session; 64-char Base64 → 48 bytes). Its use for the **CDN** payload is the last open item.
  * The per-song `CRYPT_KEY` is a 16-element `{1,2,3}` **note-obfuscation parameter**, not a cipher key.

* **Live IL2CPP introspection — `frida-il2cpp-bridge` (2026-09-17)**: the vendored `_il2cpp_bridge.js` can list assemblies/classes and **invoke managed methods without patching code**. Key results:
  * **Wine/CNG thread affinity**: BCL-crypto methods SIGSEGV when called from Frida's thread; run them on the game's main thread via `Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => …))`. This makes `da.AESEncrypt/AESDecrypt` work.
  * **`da` AES scheme verified**: AES-256-CBC/PKCS7 with **key = 32 ASCII bytes of `da.aes_key`**, **IV = 16 ASCII bytes of `da.aes_iv`**. (`da.AESEncrypt("AAAA")` → `CLbb9g2E8onb853oZrILYQ==`, reproduced exactly offline.)
  * **`da.rus` holds the live pattern**: `rjl` = `.ez` ciphertext, `rjm` = `.ezi` ciphertext, `rjn` = 48-byte base64-decoded `bundleCryptKey` (per-session).
  * **The AOT code is decrypted and readable in memory** (RVA `0x3db000`–`0x363d000`, ~52 MB) — `Il2Cpp.Method.virtualAddress` gives valid x86-64, dumpable with `_dump_code.js` to `il2cpp_code/`.
  * Still open: which method decrypts the CDN payload (candidates `qe.kha/gef/gth/lrw`, `InGameCore.dcf/dcg` all abort — see `AGENTS.md` §5).
  * **Call-graph symbolication + crypto inventory + 26-blob `a.rn*` key table** documented in `AGENTS.md` §2 (“Static Call-Graph Symbolication”).

---

## Installation & Setup

1. **Virtual Environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install UnityPy frida frida-tools pefile capstone
   ```

2. **Master Key (`true_key_1024.bin`)**:
   * The master 1,024-byte XOR decryption key (`true_key_1024.bin`) must be present in the repository root.
   * **Obtaining the Key**:
     Run the zero-hook memory harvester (`harvest_key.py`) while the game is running to extract the decrypted header from RAM and derive the key:
     ```bash
     python3 harvest_key.py
     ```
     This derives `true_key_1024.bin` via:
     $$\text{Key}[0..1023] = \text{RAM\_Decrypted\_Header}[0..1023] \oplus \text{Encrypted\_Disk\_Header}[0..1023]$$

---

## Tools & Usage

### 1. Asset & Audio/BGA Extractor (`extract_assets.py`)
Extracts FLAC/OGG audio keysounds and optional BGA `.mp4` video files directly into `extracted_assets/<song_id>/`.

```bash
# Extract keysounds/audio for a song
python3 extract_assets.py rebind

# Extract keysounds + BGA video (.mp4)
python3 extract_assets.py rebind --bga

# Extract from a specific bundle hash or file path
python3 extract_assets.py 2248f89af25f30bf92157f150a0f5bd245a2cbdc1481eb8869208f7597f56506 --bga
```

---

### 2. Song Bundle Finder & Indexer (`find_bundle.py`)
Inspects container paths and maps encrypted bundle hashes to song codenames (e.g. `rebind`, `ae_illusion`, `devote`), distinguishing between `AUDIO` (Pack 01) and `VIDEO` (Pack 02) bundles.

```bash
# Search bundles matching a song keyword or ID
python3 find_bundle.py rebind

# Search and decrypt matching bundle(s) on-demand
python3 find_bundle.py rebind --decrypt

# Force rebuild of song_index.json
python3 find_bundle.py --index
```

---

### 3. Offline Bundle Decryptor (`decrypt_all.py`)
Decrypts `.unity3d` bundle containers in bulk using `true_key_1024.bin`.

```bash
# Decrypt first 5 bundles (default limit)
python3 decrypt_all.py

# Decrypt a specific limit or specific bundle files
python3 decrypt_all.py --limit 10
```

---

### 4. Chart Harvester (`harvest_chart.py`)
Extracts the chart (`.ez`, `EZFF` note data) and the keysound index (`.ezi`, **text**) delivered dynamically from the game's CDN upon song selection. Uses read-only memory polling; **note that the deployed client loads no anti-cheat module** (verified 2026-09-16) — but **do not use `Interceptor.attach` or `MemoryAccessMonitor`**, both of which crash the game (see `tools/README.md`).

> **Naming note:** per EZ2AC convention, **`.ez` is the note chart** and **`.ezi` is the keysound index** — see *Format lineage* below.

```bash
# Launch the harvester while the game is running with Frida Gadget (port 27042)
./.venv/bin/python harvest_chart.py
```

> **Chart download pipeline (important):** Charts are not bundled in the client — they are fetched on demand from a CloudFront CDN (`game1-cdn.ez2game.co.kr`). The download URLs are **signed and expire in ~150 seconds**, so a chart must be downloaded immediately after the URL is captured from game memory. The bundled `download_file()` uses a generic UA and currently returns **HTTP 403**; the proven working path is the host-side curl fetch below.
>
> **URL/parsed-chart lifecycle (observed):** `ez_url`/`ezi_url` and the parsed note/BPM data live in `InGameCore` while playing, paused-during-play, or on the game-over screen; they are cleared on quick-restart and on continuing to the result screen, and re-fetched each time gameplay is entered from song select.

#### Host-Side CDN Fetch (`fetch_chart.sh`)
The reliable download path captures a fresh URL via Frida and immediately `curl`s it with the game's *exact* request headers (verified via `mitmproxy`). The original 403s were caused by **URL TTL expiry**, not headers — the game's headers are correct and required.

```bash
# Requires the game running (Frida Gadget :27042) with a fresh song URL visible.
# 1) Replay/pause a song so an unexpired URL is in memory, then:
bash /tmp/fetch_chart.sh
# -> saves .ezi + .ez to extracted_charts/_inproc/ with HTTP 200
```

#### Game Request Headers (from `mitmproxy`)
| Header | Value |
|---|---|
| `User-Agent` | `UnityPlayer/6000.0.78f1 (UnityWebRequest/1.0, libcurl/8.10.1-DEV)` |
| `Accept` | `*/*` |
| `Accept-Encoding` | `gzip, deflate, br` (`--compressed`) |
| `Content-Type` | `application/json` (CDN) / `application/x-www-form-urlencoded` (API) |
| `X-Unity-Version` | `6000.0.78f1` |

#### CDN File Format — OPEN RESEARCH ITEM

The CDN serves the charts **encrypted, not compressed**. A successful HTTP 200 fetch of the chart (56,000 bytes for MilK) begins with `79 5f 16 8b …` and the keysound index (18,192 bytes) with `79 de 57 7c …`, i.e. neither starts with `EZFF`; the game decrypts locally post-download.

### Format lineage (EZ2AC — `github.com/freem/ez2stuff`)

The arcade formats explain EZ2ON's file naming, and give the plaintext structure:

* **`.ez` = note chart**, magic **`EZFF`**, then `0x05` version, `0x06–0x45` internal name, `0x86` ticks/measure, `0x88` **initial BPM (float)**, `0x8C` track count, `0x8E` total ticks, `0x92` other BPM; `EZTR` per-track blocks follow.
* **`.ezi` = keysound index, and it is TEXT**: `[index] [velocity] [filename]` per line, velocity only 0 or 1 (e.g. `1 0 filename.wav`).
* **Corroboration:** MilK's `.ezi` is 18,192 B and the game reports **807 keysounds** → 22.5 bytes/line, exactly a text line's width. The index plaintext is therefore **uncompressed text of the same length as the ciphertext**.
* **Arcade `.ez` encoding (tested, negative):** from 7th Trax v1.5 the arcade encoded `.ez` as *subtract a repeating 512-byte static keystream, then reverse the file* (`ezdec_715.c` / `ezdec_720.c`). Both tables were applied to the EZ2ON payloads (subtract/add/xor × forward/reversed) → no `EZFF`, no `PK`, no text. EZ2ON does not use the arcade keystream.
* **No static keystream:** a static keystream would make two songs a two-time pad, and since both `.ezi` plaintexts are ASCII text the difference would stay low-entropy. It does not — `ct₁−ct₂` and `ct₁⊕ct₂` are random (entropy ≈ 7.96, printable ≈ 45 %) **except for the first 16 bytes, which are exactly zero**. So bytes `0x00–0x0F` are a **16-byte constant header** and the cipher is **keyed per song**.

**Cryptanalysis summary (both files):**

| Property | `.ez` (99,248 B) | `.ezi` (69,504 B) | Random baseline |
|---|---|---|---|
| Shannon entropy | 7.9983 | 7.9974 | 8.0 |
| Unique byte values | 256 / 256 | 256 / 256 | 256 |
| χ² (df=255) | 238 | 246 | ~255 |
| Zero bytes | 395 | 266 | ~272 expected |
| Size % 16 | 0 | 0 | — |
| Repeated 8-byte windows | none | none | — |
| Index of coincidence | 0.00391 | 0.00391 | 0.003906 |

**Ruled out by direct test** (at offsets 0/4/8/16, alone and after every `true_key_1024.bin` XOR variant): gzip, zlib, raw-deflate, bz2, LZMA (alone/xz/raw), LZ4, Zstd, Brotli, Snappy; single-byte XOR; the bundle XOR key (full, first-0x400-only, first-block); AES-ECB (no repeated 16-byte blocks). Unity container signatures are absent.

**Conclusion:** consistent with a **block cipher**. `bundleCryptKey` is **per-song**, not per-session (correction, 2026-09-18 — earlier notes said per-session; entering a second song changes it completely). It equals `da.rus.rjn`, and the CDN ciphertext is **deterministic per song** (re-downloading a song yields byte-identical ciphertext), so the IV is fixed.

**Status (2026-09-18) — still open, but heavily narrowed.** The payload is **confirmed encrypted** (not a native container — XOR of two different 4K SHD `.ezi` files is statistically random, 0 zero-bytes in the first 256) and **confirmed not compressed** (deflate/gzip/bz2/lzma/xz, LZ4 block+frame, Brotli — all offsets 0–32, all buffers → 0 hits). Ruled out for the key: every sliding 16/24/32-byte window of `rjn`/`bundleCryptKey` raw and ASCII, MD5/SHA1/SHA256/SHA512 derivations, the 26-entry `a.rn*` key table, `svk`–`svr`, and all `da`/`qe`/`zf` string constants — including a 1,519-key **PKCS7 padding-oracle** sweep (padding depends only on the key, so this is a strong filter) requiring validity on **both** files: **0 survivors.**

A complete scan of every `RijndaelManaged`/`AesCryptoServiceProvider` construction site finds only **12** in the binary, all accounted for (local saves, **Rewired** user-data store, API/TCP session, SharpZipLib, the inert `InGameCore.dcg`, and two factories) — **none is a chart decrypt**. Crypto is invoked virtually, so call-site scanning cannot see it; and the AES S-box exists in-process only as `global-metadata.dat` field-initialiser blobs, which points to a **bespoke managed C# AES** whose call sites static analysis cannot reach.

> ⚠️ **Do not retry `MemoryAccessMonitor` on the `da`/`da.rus` static-fields page — it crashes the game.** That page is read ~350×/second from multiple threads and the guard is one-shot, so either the guard is consumed before the decrypt runs, or re-arming produces a multi-threaded trap storm. Use hardware breakpoints (`DR0`–`DR3`) or a single cold-function hook instead. See `AGENTS.md` §2.

**Dismissed red herrings:** the `InGameCore` static `svk`–`svr` byte arrays and the per-song `CRYPT_KEY` string are **not** the CDN cipher key (`CRYPT_KEY` is a `{1,2,3}` note-obfuscation parameter). `qe.cal/fal/fam/gvf/jqv`, `qe.fan/fao/kha/lrw` and `bcg`/`bcf`/`bch` are **Rewired** `UserDataStore_File` plumbing (zip + CLZF2 + AES), not chart crypto. `da.chn`/`da.cin`/`da.cik`/`da.cqo` are `Int32->String` string-table getters. No native anti-cheat module is loaded.

---

### 5. Per-Song Snapshot (`dump_song.py`)  — recommended

Because the CDN payloads are still encrypted, this is the practical way to bank
everything the game knows about a song: it watches `InGameCore.instance` and, the
moment a new chart is fetched, it

1. **downloads the signed CDN URLs immediately** (they expire in ~150 s) and
   archives the payloads byte-exactly as served, and
2. **snapshots the in-memory state** — the raw buffers the game decrypts
   (`mem_rjl/rjm/rjn.bin`), the keysound dictionary, and the parsed note data.

```bash
# with the game running (Frida Gadget on 127.0.0.1:27042):
python3 dump_song.py                 # watch at ~2 Hz, output under extracted_charts/
python3 dump_song.py --out /data/ez2on --interval 0.4
```

Then just **play songs** — each one is captured on entry, into
`extracted_charts/<musicresourcename>_<keymode>_<levelmode>_<gamemode>/`:

| file | contents |
|---|---|
| `ident.json` | song identity, signed URLs, field counts, per-lane note counts |
| `cdn_ez_*.bin`, `cdn_ezi_*.bin` | the CDN payloads, byte-exact as served (encrypted) |
| `mem_rjl.bin`, `mem_rjm.bin`, `mem_rjn.bin` | the buffers + key the game holds in `da.rus` |
| `instrumentDic.json` | the decrypted keysound index as the game parsed it |

It is **read-only and crash-free by design**: low-rate passive polling, no hooks,
no guard pages.  A `403` on a `cdn_*` fetch just means the signed URL expired
first.

---

## Live Introspection & Capture Tools (2026-09-16)

| Tool | Purpose |
|---|---|
| `_parse_mitm.py` | mitmproxy addon: parse a saved flow file offline → API responses + CDN ciphertext (`mitm_parsed/`). |
| `_dump_pattern.py` / `_dump_api.py` | mitmproxy addons: dump `c2s_get_pattern_file` request/response pairs and specific API bodies. |
| `_decrypt_api.py` / `_decrypt_api_all.py` | Decrypt API responses with the session key (AES-CBC, ASCII key/IV) → `bundleCryptKey` + full music list. |
| `_diag.py` / `_diag.js` | Read-only `InGameCore` dump (static + instance fields, correctly via `il2cpp_field_static_get_value`) + `EZFF` heap scan. |
| `_poll_capture.py` / `_poll.js` | High-frequency poller: catches transient `bundleCryptKey`, auto-`curl`s fresh `ez_url`/`ezi_url`, periodically heap-scans for in-memory decrypted `EZFF`. |
| `_find_aes.js` / `_probe_aes.js` | Locate the runtime AES implementation (static 256-byte S-box) and enumerate `AesTransform` methods. |
| `_hook_aes2.js` | **Safe** hook on `AesTransform..ctor` (captures CDN key/IV); validates pointers with `Process.findRangeByAddress` first. |
| `_find_vy.js` / `_find_vx.js` / `_find_refs.js` / `_find_wy.js` | IL2CPP reflection helpers (member/pattern DTOs, cross-class field references). |
| `_decrypt_test.py` / `_crack_cdn*.py` | AES brute-force against captured CDN ciphertext. |

### IL2CPP tooling added 2026-09-17/18

| Tool | Purpose |
|---|---|
| `_il2cpp_bridge.js` | Vendored `frida-il2cpp-bridge@0.14.0`; concat with a driver to expose `rpc.exports.*`. |
| `onMain()` pattern (`_bridge_mt*.js`) | **Runs managed calls on the game's main thread** — required for BCL crypto under Wine/CNG (calls from Frida's thread SIGSEGV). |
| `_sym.js` | Enumerates all **176,021** methods across 97 assemblies → `virtualAddress → Class.method`. |
| `_findcallers.js` | Scans the ~76 MB code region for `E8 rel32` call sites to given targets (~100 s). |
| `_encl.js` | Maps an address to its enclosing managed method (hint only — unreliable for large offsets). |
| `_dump_code.js` / `_pattern_run.js` | Dump method bytes at `Il2Cpp.Method.virtualAddress` (`il2cpp_code/*.bin`). |
| `_staticscan.js` | **Correct** IL2CPP static-field scanner (`[reg+0xb8]` then `add reg, imm32`). |
| `_finddisp.js` | Instance-field scanner (`mov reg,[reg+disp32]`). |
| `_sbox.js` / `_klassname.js` | AES S-box memory scan; raw `Il2CppClass*` → class-name lookup. |
| `_igc.js` | `InGameCore` instance field offsets (`bundleCryptKey` 0x830, `instrumentDic` 0x550, …). |
| `_rijndael256.py` / `_rijsearch.py` | **Verified** parameterised Rijndael (Nb=8 supported; `pycryptodome` cannot). |
| `_poll_da.py` / `_poll_da.js` | **Safe** 4 Hz passive `da.rus` watcher (no guard pages) — the pattern to copy. |
| `_dcg.js` | 3-arg `(byte[],byte[],byte[])` main-thread invoker. |

> ⚠️ `_watch.js`, `_slotwatch.js`, `_slotwatch2.js` use `MemoryAccessMonitor` guard pages and **crash the game**. Kept only as evidence of what not to do.

---

## Repository Layout

```
.
├── AGENTS.md                     # full RE technical report
├── README.md
├── extract_assets.py             # ── user-facing ripper tools ──
├── find_bundle.py
├── decrypt_all.py
├── harvest_chart.py
├── harvest_key.py
├── run_dumper.sh
├── true_key_1024.bin             # master bundle XOR key
├── song_index.json               # bundle-hash → song index
├── extracted_assets/  extracted_charts/   # outputs
├── mitm_live/  mitm_parsed/      # captured CDN + API traffic
├── il2cpp_code/                  # per-method code dumps
├── data/                         # derived analysis artefacts (JSON)
├── logs/                         # captured run logs
└── tools/                        # ── investigation tooling ──
    ├── README.md                 # layout, build step, crash warnings
    ├── il2cpp/                   # frida-il2cpp-bridge + all drivers
    ├── probes/                   # passive probes (+ the crash-y hook scripts)
    ├── mitm/                     # mitmproxy addons, API decryption
    ├── crypto/                   # cipher analysis, key sweeps
    └── legacy/                   # superseded first-generation tooling
```

Investigation drivers are loaded as `bridge + driver`. Regenerate the runnable
`*_run.js` files after editing anything:

```bash
bash tools/il2cpp/build_run.sh
```

See **`tools/README.md`** for the two environment traps (module base changes per
launch; AOT code is decrypted lazily) and the list of approaches that **crash the
game** and must not be retried.

---

## Output Directory Structure

* `extracted_charts/<song_id>/`: Output folder for captured `.ezi` binary charts and `.ez` keysound maps.
* `extracted_assets/<song_id>/`: Output folder for extracted FLAC/OGG keysounds and `.mp4` BGA videos.
* `EZ2ON REBOOT R/decrypted_bundles/`: Output folder for decrypted `.unity3d` AssetBundle containers.
* `song_index.json`: Mapped index of bundle hashes to song IDs and asset types.

---

## Generative AI Usage Disclosure

This project was written with Qwen3.6 35B-A3B and Gemini 3.6 Flash. All output was reviewed by a human.

## Disclaimer

Only use for archiving purposes. All rights to game assets, audio, videos, and chart files belong to Neonovice / EZ2ON REBOOT: R developers.
