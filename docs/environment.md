# 1. Environment

> Part of the EZ2ON REBOOT:R technical report — index: [docs/README.md](README.md).

| | |
|---|---|
| Game | EZ2ON REBOOT: R — Unity 6000.0.78f1, IL2CPP, x86-64 Windows build |
| Runtime | Proton / Wine (Steam Linux Runtime `pressure-vessel`) |
| Core modules | `EZ2ON.exe`, `GameAssembly.dll`, `EZ2ON_Data/il2cpp_data/Metadata/global-metadata.dat` |
| Assets | `EZ2ON_Data/StreamingAssets/Packs/01/` (audio), `02/` (video) — ~1,231 AssetBundles |
| Instrumentation | Frida Gadget on `127.0.0.1:27042`, attach target `"Gadget"`; `.venv/bin/python` (frida, capstone, pefile, pycryptodome) |
| Anti-cheat | **Wellbia "Uncheater"** (XIGNCODE-family): managed wrapper `uncheatercsd` in `GameAssembly.dll` plus native `xnina_x64.xem`/`xmag_x64.xem` under `EZ2ON_Data/StreamingAssets/{1B0E0030-…}/`. It runs in-process and does not block the tooling, but it **does** reject a Steam emulator (Goldberg) at launch — see [`client/README.md §3`](../client/README.md). |

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
  blocks on a futex forever with no output.  `ripper/dump_song.py` runs each call on a daemon thread
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
