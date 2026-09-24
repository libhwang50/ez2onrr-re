# 4. Runtime internals

> Part of the EZ2ON REBOOT:R technical report — index: [docs/README.md](README.md).

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
  `rjm`@0x18 (`.ezi` ciphertext), `rjn`@0x20 (the 48-byte transport key — **not** the chart
  cipher key; see §3.3).
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
* `da.rpr` = API base; `da.ror` / `da.ros` = client version / build. Observed on
  screen (top right of the menus) for this install: **`2026.09.04.001 LIVE A2`** —
  the same shape the control channel's `GET /Notice?id=…&name=…&version=…` carries.

### 4.4 Symbolication & code scanning

* `tools/il2cpp/_sym.js` — enumerate all 176,021 methods (97 assemblies) →
  `virtualAddress → Class.method` (~8 s).
* `tools/il2cpp/_callers.js` — **the workhorse.** Scans the whole module for direct `E8`/`E9`
  rel32 call/jmp sites targeting given VAs, builds its own 176,021-method symbol map, and
  attributes every hit to its enclosing method (nearest preceding method VA). Full sweep
  ≈40 s. This is what located the chart decryptor (`dcf`, and its `jmp` to `dcg`).
  (A fixed-base predecessor, `_findcallers.js`, was stale every launch and was removed
  in the 2026-09-23 tools prune; `_encl.js`, whose standalone attribution `_callers.js`
  now does inline, went with it.)
* `tools/il2cpp/_staticscan.js` — the correct IL2CPP static-access signature:
  `mov r64,[r64+0xb8]` then `add r64, imm32`. Scanning the displacement form instead
  yields ~90× false positives.

### 4.4.1 Virtual dispatch is resolvable after all

IL2CPP virtual calls do **not** go through an opaque thunk. The codegen loads a
`(methodPtr, methodInfo)` pair straight out of the klass struct:

```asm
mov r8, [obj]            ; klass  (object header @ +0)
mov r9, [r8 + SLOT]      ; methodPtr
mov r8, [r8 + SLOT + 8]  ; methodInfo
call r9
```

So a virtual call site is a plain `mov reg,[reg+disp32]` — scannable, given the slot.
Slots are **not** globally unique (they are per-class), but **inherited slots keep their
offset in derived classes**. For anything deriving from `SymmetricAlgorithm`:

| slot | method |
|---|---|
| `0x1a8` | `set_BlockSize` |
| `0x1d8` | `set_IV` |
| `0x1f8` | `set_Key` |
| `0x238` | `set_KeySize` |
| `0x258` | `set_Mode` |
| `0x278` | `set_Padding` |

Find a slot with `tools/il2cpp/_slotfind.js` (dumps the klass struct and locates a method’s
VA at its 8-byte-aligned offset). Reading a klass correctly requires the Il2CppClass layout
— `name`@0x10, `namespaze`@0x18, `static_fields`@0xb8 — via `_probe_cls.js` / `_mem.js`.

> **JS gotcha that cost time:** `x >>> 32` is `x >>> 0` in JavaScript (shift counts are mod
> 32). Use `Math.floor(x / 4294967296)` for the high word of a 64-bit address.

### 4.4.2 Static fields

`tools/il2cpp/_statics.js` lists a class’s static fields with static-region offset, type,
and live length/head for `Byte[]` values. This is how the chart key was extracted:
`InGameCore` statics `svq`(64)/`svr`(16) are the mask tables and `svo`(32)/`svp`(16) are the
AES key/IV. Related: `_mem.js` (raw reads, klass name, byte-array dumps),
`_methods.js` (method VA + field offset listing), `_vt.js` (crypto-class VAs + module base).

### 4.5 Metadata

`global-metadata.dat` (26,226,972 B) has **no `0xFAB11BAF` magic**, so Il2CppDumper aborts.
Only part of the file is obfuscated; from ≈18.2 MB it contains plaintext type/method/field
names (which is how the DTO structure was recovered). The AOT machine code is **not**
needed from it — it is readable directly from process memory.
