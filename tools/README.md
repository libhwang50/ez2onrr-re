# `tools/` — reverse-engineering & analysis tooling

Everything here is investigation tooling, kept separate from the user-facing
ripper scripts at the repository root (`extract_assets.py`, `find_bundle.py`,
`decrypt_all.py`, `harvest_chart.py`, `harvest_key.py`).

## Layout

| directory | contents |
|---|---|
| `il2cpp/` | `frida-il2cpp-bridge` (`_il2cpp_bridge.js`) plus all IL2CPP drivers: symbolication (`_sym.js`, `_encl.js`), **call-site scanning and enclosing-method attribution (`_callers.js` — the workhorse)**, **klass/vtable inspection (`_slotfind.js`, `_probe_cls.js`)**, **static-field extraction (`_statics.js`, `_mem.js`, `_methods.js`, `_vt.js`, `_clsstr.js` — static string values)**, code dumping (`_dump_code.js`), field/class inspection (`_igc.js`, `_tables.js`, `_cova.js`, `_namemap.js`, `_klassname.js`), scanners (`_staticscan.js`, `_zfscan.js` — klass-verified static-write scan, `_finddisp.js`, `_sbox3.js`, `_asascan.js`), one-shot probes (`_zfdbg.js`, `_zflit.js` — string-literal thunks, `_zfinst.js`), the private server's session-key reader (`_sesskey.js`), and older live-introspection tools (`_diag.py`, `_poll_capture.py`). |
| `probes/` | Passive runtime probes (safe) and the hook experiments. |
| `mitm/` | mitmproxy addons (`_cdn_rewrite.py` rewrite oracle, `_capture_all.py` full-corpus capture), flow parsing (`_replay_extract.py` — native `-w` dump → per-flow JSONL + bodies), API decryption. |
| `crypto/` | Cipher analysis. `_chart_cipher.py` is the **reference implementation of the (now-solved) CDN chart cipher** — mask + AES-256-CBC; the production CLI lives at the repo root as `decrypt_chart.py`. Also a verified parameterised Rijndael (`_rijndael256.py`, `_rijsearch.py`), key sweeps, brute-forcers. |
| `legacy/` | Superseded first-generation tooling (in-process WinHTTP download, early camera/field dumpers). |
| `../data/` | Derived analysis artefacts (JSON: symbol maps, key-candidate tables, scan results). |
| `build/` | **Generated** runnable drivers (git-ignored) — one flat directory, so the source dirs stay clean. |
| `../data/` | Derived analysis artefacts (JSON: symbol maps, key-candidate tables, scan results). |
| `../logs/` | Captured run logs from the probe campaigns. |

## Running a driver

A driver is loaded by concatenating it **after** the bridge, because
`rpc.exports.*` must be defined after `Il2Cpp` exists.  The runnable form is
generated for you:

```bash
bash tools/il2cpp/build_run.sh        # regenerates tools/build/*_run.js
```

Generated drivers land in **`tools/build/`** (one flat, git-ignored directory);
the source directories contain only hand-written code.

**Run `build_run.sh` after editing any driver** — a hand-edited `*_run.js` is
overwritten.  The `*_run.js` files are generated artefacts (git-ignored).

```python
import frida
dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
s   = dev.attach("Gadget")
sc  = s.create_script(open("tools/il2cpp/_sym_run.js").read())
sc.load()
print(sc.exports_sync.sym(["0x6ffff..."]) if False else "ready")
```

Or just use the runner, which resolves and loads `tools/build/<driver>_run.js`:

```bash
python3 tools/_r.py _callers all '["0x6ffff2d97380"]'      # callers of one VA, attributed
python3 tools/_r.py _statics statics '"Assembly-CSharp"' '"InGameCore"'   # static fields
python3 tools/_dis.py 0x6ffff2d971b0 0x1e0                  # disassemble a range
```

`tools/_dis.py` reads live module bytes through the gadget and disassembles with capstone,
so it needs no local copy of `GameAssembly.dll`.

## ⚠️ Things that crash the game — do not repeat

Three separate approaches have killed the process. They are kept here as
evidence, not as tools:

* **`MemoryAccessMonitor` guard pages** (`probes/_watch.js`, `probes/_slotwatch*.js`)
  — any page touched per-frame (e.g. `da`'s static-fields page, read ~350×/s from
  several threads) becomes a trap storm under Wine and takes the game down.
* **`Interceptor.attach` on anything** (`probes/_hook_aes*.js`,
  `probes/_hookcrypto.js`) — crashed on a hot BCL function, and again on
  *cold* cipher constructors that run once per cipher.
* **High-frequency in-process polling** (the 10 ms `Il2Cpp.perform` loop) on top
  of either of the above.

Two further hazards, learned later, that are **not** about hooking:

* **Killing a watcher without detaching.** SIGTERM does not run Python `finally`
  blocks, so `timeout 30 python3 dump_song.py` leaves the Frida agent resident and
  wedges the gadget's message loop. `dump_song.py` and `harvest_chart.py` install
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
