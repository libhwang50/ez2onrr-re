# `client/` — Frida-free session-key hand-off

The private server needs each client's API session key (`zf.aes_key` / `zf.aes_iv`).
The client generates it locally and only ever sends it RSA-wrapped in
`c2s_login.data`, encrypted under a public key baked into the build. The server
owns a keypair; the client must be made to encrypt to **our** public key. That is
the whole job of this directory: rewrite the live `zf.publicKey` string.

No hooks, no code patches, no Frida, no root — just an in-place rewrite of the
`<RSAKeyValue>` managed string (same byte length, so no reallocation).

```
server:  python server/_rsa.py init          # writes data/server_rsa_{private.pem,public.xml}
server:  python server/app.py --port 8081    # standalone; c2s_login RSA-decrypts the key
client:  EZ2_REMOTE=http://<server>:8081 mitmdump -s server/_relay.py   # forward game hosts
client:  <drop-in version.dll>  OR  ez2on_patch.py --patch --watch
```

## 1. Drop-in `version.dll` (Windows + Proton) — the deployment artifact

The game loads `version.dll` from its own folder (that slot currently holds the
Frida Gadget, with `version.config`). `UnityPlayer.dll` imports
`GetFileVersionInfoSizeA` / `GetFileVersionInfoA` / `VerQueryValueA` from it, so
the replacement is a proxy that forwards those to the system DLL and rewrites
`zf.publicKey` from a background thread.

Build (Arch host, one-time toolchain install):

```bash
sudo pacman -S --needed mingw-w64-gcc
python server/_rsa.py init                 # keypair (once; fixed for the server)
bash client/patcher/build.sh               # -> client/patcher/version.dll
```

Install for local testing:

```bash
bash client/patcher/install.sh patcher   # install (keeps the Gadget as version.dll.gadget)
bash client/patcher/install.sh status     # what is live now
bash client/patcher/install.sh gadget     # restore the Frida Gadget
```

**Under Proton/Wine the app-dir `version.dll` is ignored unless you force it** —
Wine resolves `version.dll` to its own builtin, so the file in the game folder is
never loaded. Add this to the game's Steam launch options (Proton *appends* its own
overrides, so this merges):

```
WINEDLLOVERRIDES=version=n,b %command%
```

On real Windows no override is needed (the app directory is searched first and
`version.dll` is not a KnownDLL). Confirm it loaded by watching for a fresh
`[pid …] version.dll proxy attached` line in `ez2on_patch.log` — its mtime alone
tells you whether the DLL ever ran.

On launch the patcher writes `ez2on_patch.log` next to the exe and rewrites the
key within a second or two of the IL2CPP runtime starting.

## 2. `ez2on_patch.py` — host-side patcher (dev tool / Windows fallback)

Reads the target process memory directly (`/proc/<pid>/mem` on Linux,
`VirtualQueryEx` + `Read/WriteProcessMemory` on Windows) and overwrites the
`<Modulus>`/`<Exponent>` values in place.

```bash
python client/ez2on_patch.py --scan                 # report publicKey hits
python client/ez2on_patch.py --patch --watch        # patch as soon as it appears
```

Linux note: `ptrace_scope=1` means a non-parent process needs root, so for a
Proton game run `sudo` (or use the DLL, which runs in-process and needs
nothing). On Windows it works same-user, no admin.

## 3. Playing without a Steam account (Goldberg)

Users who do not own the game on Steam (and therefore have no SteamID) can still
join a private server by running the client under a Steam emulator. The build is
well suited to it:

* it uses **Steamworks.NET** and ships the emulatable Unity plugin
  `EZ2ON_Data/Plugins/x86_64/steam_api64.dll` (this is the file an emulator
  replaces);
* `EZ2ON.exe` has **no SteamStub `.bind` section** — no Steamless unpack step;
* `RestartAppIfNecessary` is **not called**, so there is no "relaunch through
  Steam" DRM gate;
* the only Steam data the private server ever sees is the **SteamID** and the
  auth ticket in `c2s_login`, and the server **does not validate the ticket**.

Setup (Goldberg, per client):

1. Replace `EZ2ON_Data/Plugins/x86_64/steam_api64.dll` with Goldberg's build
   for that file.
2. Put `steam_appid.txt` containing `1477590` in the game root (or where your
   Goldberg version reads it — its `steam_settings/` folder).
3. Give the install a **unique SteamID64** and persona name in Goldberg's
   config (`steam_settings/`; the exact filenames depend on the Goldberg
   version, e.g. `configs.user.ini` / `configs.main.ini`, `user_steam_id.txt`,
   `account_name.txt`). Spoof ownership of `1477590` if your config asks.
4. Launch the game. Steamworks init succeeds against the emulator, the client
   reads its (fake) SteamID/persona and sends them to whichever server it is
   pointed at, and the private server accepts them.

The game touches `SteamUser`, `SteamFriends`, `SteamApps`, `SteamUserStats`,
`SteamUtils` and `GetAuthSessionTicket` — a modern Goldberg covers all of them.

Caveats:

* **Unique SteamID is mandatory.** Two users sharing one ID (e.g. Goldberg's
  default) collide in the server's session registry and progression store; set a
  distinct one per install.
* The patcher `version.dll` and Goldberg coexist — different slots — so install
  Goldberg's `steam_api64.dll` *and* (if the server uses the RSA hand-off) the
  patcher `version.dll` (with `WINEDLLOVERRIDES=version=n,b` under Proton).
* The emulated identity is **self-asserted**. That is fine for a friends/LAN
  server; a public server must not trust the claimed SteamID and needs the
  server-issued identity token planned for that deployment.

## Why the RSA block is the key

`c2s_login.data` is exactly 256 B (2048-bit) on every capture — see `server/_rsa.py`
and §3.1. Once the client encrypts to our key, the plaintext is **not** a bare
`key||iv` blob but the client's **141-byte login JSON**:

```json
{"steamid":"76561199429391557","appid":"1477590",
 "version":"2026.09.04.001","key":"<32 uppercase hex>","iv":"<16 uppercase hex>"}
```

`_pserver.py`'s login handler parses it, writes `server/session_key.json`, and every
later endpoint is served under it — and the `steamid` is handed to us for free, which is
what a multi-user session registry keys on. The harvester becomes optional
(or unnecessary entirely).

Confirm the swap is really active with the standalone probe, independent of the server:

```bash
mitmdump -s server/re/_login_probe.py      # then launch the game
cat server/login_probe.log              # KEY_IV_HEX == hypothesis confirmed
```

A block that is **rejected** means the DLL is not loaded; a block that decodes but is
**not** the key/iv JSON means the client build changed shape.
