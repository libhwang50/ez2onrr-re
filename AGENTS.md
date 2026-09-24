# EZ2ON REBOOT:R — project brief

Technical report and toolset for **EZ2ON REBOOT:R** (Unity 6000.0.78f1, IL2CPP,
x86-64). The full write-up lives in **`docs/`** (start at
[`docs/README.md`](docs/README.md)); this file is the short brief and the rules
that apply everywhere. Section numbers like `§3.1` resolve in `docs/`.

| guide | |
|---|---|
| [`docs/`](docs/README.md) | the technical report, split by topic |
| [`README.md`](README.md) | user-facing: ripping assets, charts and rendering |
| [`server/README.md`](server/README.md) | the private server — running, Docker, identity, offline recipe |
| [`client/README.md`](client/README.md) | the Frida-free patcher, and Goldberg for players with no Steam account |
| [`tools/README.md`](tools/README.md) | the reverse-engineering harness |

## Layout

```
ripper/    archiving tools — assets, bundles, charts, render (see README.md)
server/    the private server (standalone HTTP(S)/ASGI) + capture automation
server/re/ investigation/diagnostics used while developing the server
client/    the Frida-free version.dll patcher
tools/     the reverse-engineering toolbox (Frida drivers, mitm, crypto)
docs/      this technical report
deploy/    Caddyfile for the optional TLS profile
```

## Ground rules (anything touching the live game)

* **Read-only, always.** `Interceptor.attach` and `MemoryAccessMonitor` have
  crashed the game on every attempt — including cold, once-per-launch functions.
  Use managed invocation via the bridge, plus **≤4 Hz host-side polling**, and
  never **hold** managed objects across invocations (the GC does not know about
  them). Read backing arrays instead of walking `Dictionary` state.
* **`onMain()` is only for the OS crypto provider** (Wine/CNG thread affinity).
  Elsewhere it has livelocked the game's main thread under Proton.
* **Bound every RPC** — a livelocked hijack never returns.
* When the read path dies it does **not** recover: `failed to run on thread`,
  `couldn't collect attached threads`, or `script has been destroyed`. Detect and
  stop, do not keep polling.
* Rebuild symbol maps **every session** (the module base moves per launch) and
  treat AOT code as **lazily decrypted per method**.
* The game defines a global `Module`/`GameAssembly` that **shadows Frida's** —
  always use `Process.getModuleByName`.

Detail and the full crash list: [docs/environment.md](docs/environment.md) and
[`tools/README.md`](tools/README.md).

## Current state

Every layer is solved: AssetBundle decryption, keysounds/BGA, the API session
cipher, the CDN chart cipher, and the login key hand-off. `server/` serves a
complete offline session — login → music list → profile → chart download →
leaderboard — with per-user progression and server-issued accounts, and does
**not** need Frida (the `version.dll` patcher handles the key hand-off). Open
items: [docs/status.md](docs/status.md).
