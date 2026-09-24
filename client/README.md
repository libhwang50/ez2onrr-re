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
server:  mitmdump -s server/_pserver.py      # offline default; c2s_login now RSA-decrypts the key
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

## Why the RSA block is the key

`c2s_login.data` is exactly 256 B (2048-bit) on every capture — see `server/_rsa.py`
and AGENTS.md §3.1. Once the client encrypts to our key, the plaintext is **not** a bare
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
mitmdump -s server/_login_probe.py      # then launch the game
cat server/login_probe.log              # KEY_IV_HEX == hypothesis confirmed
```

A block that is **rejected** means the DLL is not loaded; a block that decodes but is
**not** the key/iv JSON means the client build changed shape.
