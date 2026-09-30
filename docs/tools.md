# 5. Tools

> Part of the EZ2ON REBOOT:R technical report — index: [docs/README.md](README.md).

User-facing (repo root):

| Tool | Purpose |
|---|---|
| `ripper/extract_assets.py` | extract keysounds (FLAC/OGG) and `--bga` videos |
| `ripper/find_bundle.py` | map bundles → songs (`--index`, `--decrypt`, `--decrypt-all`) |
| `ripper/capture.py` | **capture charts** — interactive, Frida-free: harvest-mode relay + memory harvester, files each song you play into `extracted_charts/`; `--passthrough` forwards everything upstream so it needs no `server/data/` |
| `ripper/collect.py` | **collect official responses** — passive recording proxy for testers: forwards every game-host request to the **official** server (never the private one) and writes request/response bodies + the live session key to `collected/<timestamp>/`, zipped on exit for submission. Unpatched client required; `--cdn-body`/`--max-body` control body capture |
| `ripper/collect_read.py` | **read a submission** — list/decrypt a `collect.py` bundle (directory or zip); `--path`/`--host` filter, `--dump DIR` writes the decrypted JSON. Login responses decrypt; login requests stay RSA-wrapped |
| `ripper/decrypt_chart.py` | **decrypt CDN payloads** → `.ez` / `.ezi` plaintext (library + CLI); `--archive` completes a whole capture tree, `--check` audits it without writing |
| `ripper/parse_chart.py` | **read decrypted charts** — `.ez` note charts and `.ezi` keysound indexes, as a summary, JSON, or note listing |
| `ripper/chart_labels.py` | **name charts** — decrypt captured API traffic into `chart_labels.json` (song name, key mode, difficulty) |
| `ripper/check_charts.py` | **audit the captures** — chart identity vs the `<keymode>/<difficulty>/` it is filed under, missing artifacts, and `ident.json` disagreeing with the chart on disk. Catches the mislabelling bug that filed a 4K chart under `5k/shd`; exits non-zero, so it can gate a batch |
| `ripper/render_song.py` | **render a song** — plays every note's keysound at its scheduled time; `--assets auto` matches keysounds by content |
| `ripper/visualize_song.py` | **visualise a render** — mp4 with keysounds, lanes and progress overlaid on the BGA; player-lane rows are bright, auto-played rows dimmed (`--no-auto-dim` to disable); bulk-renders a whole song dir or `--all`, with `--skip-existing`/`--force` |
| `ripper/song_meta.py` | resolve a song's title/composer — by resource name via the API music list (`c2s_get_gameinfo`, exact + per-game-mode MUSIC_ID) with display-title folding/prefix fallbacks |

Frida live-game tooling — **RE only**, needs `requirements-frida.txt`:

| Tool | Purpose |
|---|---|
| `tools/live/dump_song.py` | **per-song snapshot** — byte-exact CDN archive, decrypted plaintext, `da.rus` buffers, plus the song/mode/difficulty label read from the running game. `instrumentDic.json` only with `--read-instrument-dic`; stops the watch when the read path dies |
| `tools/live/harvest_key.py` | derive `true_key_1024.bin` from live memory (validated against the bundles on disk) |
| `tools/live/harvest_metadata.py` | dump the game's song metadata table (title, composer) → `music_names.json` |
| `tools/probes/_poll_da.py` | safe 4 Hz `da.rus` watcher — the pattern to copy |

Private server (see **`server/README.md`** for the full guide):

| Tool | Purpose |
|---|---|
| `server/_pserver.py` | **the private server core** — transport-neutral game logic that stubs `game1-play` / `game1-rank` / `game1-cdn` server-side; run via `server/app.py` (standalone) or the client relay |
| `server/re/_capture_addon.py` | **the mitmproxy capture relay** — wraps the offline core: forwards `login`/`pattern`/uncached CDN upstream and files the returning CDN bodies into `extracted_charts/`. With `passthrough_endpoints.txt` set to `all` it forwards every game-host request instead, so capture needs no server data. Driven by `ripper/capture.py` (and, for RE, `_sweep.py`). No longer the server |
| `server/_rsa.py` | **the RSA hand-off** — server keypair (`init`/`show`) and a **strict** raw-RSA decode of `c2s_login.data` (the earlier `cryptography` PKCS#1 v1.5 call was not a validity oracle — 82% of random blocks "decrypted"). `selftest` guards the oracle; `decrypt <block>` decodes one |
| `server/re/_login_probe.py` | **the decisive experiment**: a mitmproxy addon that captures every `c2s_login`, strict-decodes its `data` block and reports whether the patcher is active. This is how the login JSON was pinned |
| `server/re/_harvest_mem.py` | **Frida-free session key (fallback)**: scans the game's memory for the `"key":"…","iv":"…"` JSON the client builds for login → `server/session_key.json`. Tracks relaunches/rotations, keeps the last key (the JSON is transient). Linux needs `ptrace_scope=0`/root; Windows is same-user |
| `server/re/_harvest_session.py` | Frida bridge: polls `zf.aes_key`/`aes_iv` at 1 Hz → `server/session_key.json` (the client generates the API session key locally; it is absent from the HTTPS wire, though it may be handed over on the raw packet channel — §3.1). Also owns the **one-session command channel**: it polls `server/cmd.json` and answers in `server/cmd_result.json`, so memory probes never need a second Frida session (which crashes the game). Restores the default SIGINT handler while an RPC runs, so Ctrl-C aborts a slow scan and detaches cleanly |
| `server/re/_sweep.py` | **RE-only, machine-specific auto macro** — drives the game through the list (Niri + `xwayland-satellite` only; everyone else uses `ripper/capture.py`). Captures are filed by `_capture_addon.py`; the server log is the sensor, guarded by a focused-window check, with `--calibrate` that deduces the difficulty/keymode keys from the request JSON |
| `server/re/_coverage.py` | **audit chart coverage** — songs covered vs the 601-song music list (coverage is per *song*: one capture serves every variant), writes a capture queue, and parses `pserver.log` to verify what a capture run actually asked for |
| `server/_build_data.py` | rebuild `server/data/` from local captures — decrypted API templates, the chart→CDN map (47 variants / 15 songs), profile overrides |
| `server/re/_exp.py` | the experiment knobs: `hybrid on/off`, `urls now/skew/future/expire/noparams/host`, `bck harvested/stale/garbage/empty/literal:…`, `off` (mutations only), `reset`. Read per request — no restart. **The offline core's default is already fully offline** (`urls now` + `bck mint`, no passthrough; chart matching stays `exact`); an absent knob means the default, `off`/`none` turns a piece of it off. `off` deliberately does NOT touch the hybrid setting |
| `server/re/_mem.py` | drive the harvester's command channel: `findhex` (byte pattern over code first, then r--, rw-; default budget 16 GB, reports `budgetExhausted`), `findlea` (rip-relative `lea` to an address), `findlit` (base-free, keyed on `mov r8d,<len>`), `findthunk`, `readbytes`, `bck` (locate the session token in memory) |
| `server/re/_stub443.py` | loop-proof TLS stub for the game's **un-proxied** TLS channel to `game1-rank.ez2game.co.kr:443`, with a certificate signed by the local mitmproxy CA (the client accepts it — no pinning) |
| `server/re/_stub9902.py` | capturing TCP relay/stub for the raw packet/battle channel (`battle_server.txt`) — where the client's `sendaes,` key hand-off is expected to land (§3.1). Logs both directions |
| `server/re/_rawchannel.sh` | redirects that hostname and the raw IP into `re/_stub443.py` (`on`/`test`/`status`/`off`) |

Investigation tooling — layout, build step and crash warnings: **`tools/README.md`**.
Drivers are loaded as `bridge + driver` and regenerated with
`bash tools/il2cpp/build_run.sh`.

Notable: `tools/crypto/_rijndael256.py` (verified Nb=8 Rijndael; `pycryptodome` cannot do it).
The 2026-09-23 `tools/` prune removed `legacy/`, the one-off probe campaigns, the failed
crypto sweeps and the superseded fixed-base scanners; they live on in git history.
