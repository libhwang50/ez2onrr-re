# `tools/` — reverse-engineering & analysis tooling

Everything here is investigation tooling, kept separate from the user-facing
ripper scripts at the repository root (`extract_assets.py`, `find_bundle.py`,
`dump_song.py`, `harvest_key.py`).

The directory was pruned on 2026-09-23: the one-off probe campaigns, failed
crypto sweeps and first-generation scripts were removed. What remains is the
canonical set that the root tools, the private server and the current open work
actually use. Deleted work is recoverable from git history; the important
*findings* from it are kept as prose below and in `AGENTS.md`.

## Layout

| directory | contents |
|---|---|
| `il2cpp/` | `frida-il2cpp-bridge` (`_il2cpp_bridge.js`) plus the IL2CPP drivers: symbolication (`_sym.js`, `_namemap.js`, `_methods.js`), **call-site scanning and enclosing-method attribution (`_callers.js` — the workhorse)**, **klass/vtable inspection (`_slotfind.js`, `_probe_cls.js`, `_vt.js`)**, **static-field extraction (`_statics.js`, `_mem.js`, `_staticscan.js`, `_clsstr.js` — static string values)**, string hunting (`_findstr.js` — the `patternjson` scanner), the per-song dump driver (`_dumpsong.js`) and the music-table dumper (`_musicdic.js`), and the private server's session-key reader **and memory-probe toolkit** (`_sesskey.js`). |
| `probes/` | `_poll_da.py` — the safe 4 Hz host-side poll loop, the pattern for any new passive watcher. (The hook/guard-page experiments were deleted; never re-add them, see the crash notes below.) |
| `mitm/` | mitmproxy addons (`_cdn_rewrite.py` rewrite oracle, `_capture_all.py` full-corpus capture), flow parsing (`_replay_extract.py` — native `-w` dump → per-flow JSONL + bodies), API decryption (`_decrypt_api.py`, `_decrypt_api_all.py`). |
| `crypto/` | Cipher analysis. `_chart_cipher.py` is the **reference implementation of the solved CDN chart cipher** — mask + AES-256-CBC; the production CLI lives at the repo root as `decrypt_chart.py`. `_rijndael256.py` is the verified parameterised Rijndael (Nb=8). |
| `build/` | **Generated** runnable drivers (git-ignored) — one flat directory, so the source dirs stay clean. |
| `../data/` | Derived analysis artefacts (JSON: symbol maps, key-candidate tables, scan results). |
| `../logs/` | Captured run logs from the probe campaigns. |

Drivers used by shipped tools, do not rename: `_sesskey.js` (the harvester),
`_dumpsong.js` (`dump_song.py`), `_musicdic.js` (`harvest_metadata.py`),
`_statics.js` (`chart_labels.py`), `_findstr.js` (`AGENTS.md` §3.2), `_poll_da.js`
(`tools/probes/_poll_da.py`).

## Running a driver

A driver is loaded by concatenating it **after** the bridge, because
`rpc.exports.*` must be defined after `Il2Cpp` exists. The runnable form is
generated for you:

```bash
bash tools/il2cpp/build_run.sh        # regenerates tools/build/*_run.js
```

Generated drivers land in **`tools/build/`** (one flat, git-ignored directory);
the source directories contain only hand-written code. **Run `build_run.sh`
after editing any driver** — a hand-edited `*_run.js` is overwritten.

Or just use the runner, which resolves and loads `tools/build/<driver>_run.js`:

```bash
python3 tools/_r.py _callers all '["0x6ffff2d97380"]'                    # callers of one VA, attributed
python3 tools/_r.py _statics statics '"Assembly-CSharp"' '"InGameCore"'  # static fields
python3 tools/_dis.py 0x6ffff2d971b0 0x1e0                               # disassemble a range
```

`tools/_dis.py` reads live module bytes through the gadget and disassembles with
capstone, so it needs no local copy of `GameAssembly.dll`.

### `_sesskey.js` — the one-session memory-probe toolkit

Because a second Frida session crashes the game, all live probing goes through the
harvester's session. `server/_harvest_session.py` polls `server/cmd.json` once a
second, calls the matching export and writes `server/cmd_result.json`;
`server/_mem.py` is the client for it:

```bash
python server/_mem.py findhex "38 43 4e 32 36"     # byte pattern (code ranges first)
python server/_mem.py findhex <addr-pattern> 16384  # with an explicit MB budget
python server/_mem.py findlea 0x71616d97            # rip-relative lea to an address
python server/_mem.py findlit 17 0x71616d9c         # `mov r8d,<len>` sites (base-free)
python server/_mem.py findthunk 0x71616d97          # mov edx,<off> + call, all bases
python server/_mem.py readbytes 0x137365560 256     # hex + ascii dump
python server/_mem.py bck                           # locate the session token in memory
python server/_mem.py whowrites 0x798               # sites referencing [reg+disp]
python server/_mem.py callers 0x6ffff2e87ec0        # chunked E8/E9 sweep + attribution
python server/_mem.py method 0x6ffff2fa7327         # name the method containing an address
python server/_mem.py zfstatics zf                  # every static field of a class + values
```

`whowrites`/`callers`/`method` are chunked internally, so Ctrl-C between chunks is
safe; `zfstatics` is how the session-scoped statics (the API key/IV and anything
else `zf` holds) are read without walking `Dictionary` state.

Behaviour worth knowing before trusting a result:

* **`findhex` scans `r-x` first, then `r--`, then `rw-`.** It used to do the reverse
  with a 2 GB budget, so on a process with more heap than that it returned `hits=0`
  for code/pointer searches while never having looked at the code. It now defaults
  to 16 GB and reports `budgetExhausted`.
* **AOT code is decrypted per method**, so a method that has not executed is
  invisible to any scan — trigger the code path first (e.g. produce the error you
  are chasing), then scan.
* Literals in this build live in an **anonymous runtime mapping**, so code cannot
  reach them with a RIP-relative `lea`: expect a runtime base + offset (hence
  `findlit`/`findthunk`) — and `findlea` returning nothing is normal for them.
* The driver restores the default `SIGINT` handler while an RPC runs, so Ctrl-C
  aborts a slow scan and detaches cleanly instead of looking hung.
* A second Frida session still **crashes the game** — never bypass the command
  channel, however tempting it looks for a quick probe.

## ⚠️ Things that crash the game — do not repeat

Three approaches killed the process repeatedly; their scripts were deleted, but
the lesson stays:

* **`MemoryAccessMonitor` guard pages** — any page touched per-frame (e.g. `da`'s
  static-fields page, read ~350×/s from several threads) becomes a trap storm under
  Wine and takes the game down.
* **`Interceptor.attach` on anything** — crashed on a hot BCL function, and again on
  *cold* cipher constructors that run once per cipher.
* **High-frequency in-process polling** (the 10 ms `Il2Cpp.perform` loop) on top
  of either of the above.
* **Attaching during the game's early startup** (before the main window exists)
  — even a read-only bridge script kills the process instantly, no crash
  handler. This bit the private server's auto-re-attaching key harvester, which
  now waits for the Gadget's TCP port to be listening continuously for a grace
  period (`EZ2_HARVEST_GRACE`, 15 s default) before attaching
  (`server/_harvest_session.py`).

Two further hazards, learned later, that are **not** about hooking:

* **Killing a watcher without detaching.** SIGTERM does not run Python `finally`
  blocks, so `timeout 30 python3 dump_song.py` leaves the Frida agent resident and
  wedges the gadget's message loop. `dump_song.py` installs
  SIGTERM/SIGINT/SIGHUP handlers that detach before exiting — keep that guard when
  writing new watchers, and prefer a clean Ctrl-C over `kill`.
* **Invoking list methods while the game is still building the list.** `normalLanes`
  was read by calling `get_Item`/`get_Count` on `normalNoteData`'s inner lists during
  song load, which once returned **five lanes for a 4-lane chart** — proof the read
  landed mid-mutation. `dump_song.settle()` now waits for the cheap counts to stop
  changing before touching the lanes, and reads them once.

**Safe alternatives:** read-only memory reads, managed invocation through the
bridge on the game's main thread (`onMain()`), and low-rate (≤4 Hz) passive
polling from the host (`probes/_poll_da.py` is the pattern to copy).

## ⚠️ Two environment traps

* **The module base changes per launch** (observed `0x6ffff23c0000` and
  `0x6ffff2340000` — an `0x80000` shift). Method VAs are `base + RVA`, so a
  symbol map built in one session is wrong in another. **Always query the base
  and the method VAs in the same run as any call-site scan.**
* **AOT code is decrypted lazily, per method.** A code scan silently misses any
  method that has not yet executed in that process.
