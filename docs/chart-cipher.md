# 3.3 CDN payload cipher & 3.4 MITM oracle

> Part of the EZ2ON REBOOT:R technical report — index: [docs/README.md](README.md).

**The cipher is `mask ∘ AES-256-CBC/PKCS7`, with the key and IV baked into the binary.**
Decryptor: `ripper/decrypt_chart.py`.

```
plaintext = AES_256_CBC_decrypt( unmask(ciphertext), key=<svk|svm|svo>, iv=<svl|svn|svp> )
```

**Stage 1 — `unmask`.** A data-independent, one-pass XOR mask, exactly 64 rounds per
byte. It depends only on the byte index `ebx`, never on the key or the data, so it is a
fixed keystream. Tables are the statics `InGameCore.svq` (64 B) and `InGameCore.svr`
(16 B): `S[i] = svr[svq[i] & 0xf] ^ svq[i]`, and for each `ebx`

```
r_i = (ebx * i) % 255 ;  if r_i % 10 == 0: r_i = 12      # the `cmove` at 0xac729b
mask(ebx) = XOR over i in 0..63 of ( S[i] ^ r_i ^ (ebx & 0xff) )
```

**Stage 2 — AES-256-CBC/PKCS7**, key and IV from one of **three static pairs**, all in
`InGameCore`:

| pair | observed on |
|---|---|
| `svk`/`svl` | Engine 4K SHD, Finite 5K HD (62 of the archived songs) |
| `svm`/`svn` | Change My World 4K SHD, Hyper Magic 4K SHD (52) |
| `svo`/`svp` | Conflict 4K SHD, Rebind 4K SHD (57) |

**The pair is selected per payload by validation, not recorded anywhere.** The game does
not store a key index; `bundleCryptKey` is identical across songs that use different pairs,
and the CDN path bucket differs even between a song's own `.ez` and `.ezi` while the pair
does not — so neither is the selector. For any given payload exactly one pair yields valid
PKCS7 padding, so `decrypt_chart.decrypt()` tries all three and accepts the one whose
plaintext has valid padding **and** looks like a chart (`EZFF`) or an index (printable
`[index] [velocity] [filename]` lines). `decrypt_named()` also returns which pair matched.
Both stages work **in place** on the whole buffer.

**Where it lives.** `InGameCore.dcf` (RVA `0xac71b0`) is the entry point: it runs the
64-round mask and then **tail-`jmp`s** into `InGameCore.dcg` (RVA `0xac7380`), which
configures `AesCryptoServiceProvider` — `set_BlockSize(0x80)`, `set_KeySize(0x100)`,
`set_Key`, `set_IV`, `set_Mode(CBC=1)`, `set_Padding(PKCS7=2)`, `CreateDecryptor()`.
Callers: the `ft.MoveNext` coroutine and `ff.cuc`.

**Verification (end-to-end).** `cur_conflict_ez_url.ez` → `EZFF` magic, name `4-shd`,
BPM `160.0`, 64 tracks, 64 `EZTR` blocks, valid PKCS7. `cur_conflict_ezi_url.ezi` →
2719 plaintext keysound lines whose `index → filename` mapping matches the game's own
parsed `instrumentDic` **2719/2719**. Engine (`svk`/`svl`) → `EZFF` v7, BPM `174.0`,
64 tracks, 865 keysounds matching an `instrumentDic` count of 865. Four payloads across
three songs, two key pairs, all four decoded correctly.

#### Corrections to earlier conclusions

| Earlier claim | Reality |
|---|---|
| "per-song key" (`bundleCryptKey` / `da.rus.rjn`) | **No.** The chart key/IV are the **static** `svo`/`svp`. `rjn` is a transport/audit record (§4.2) and is not the chart key. |
| "static analysis cannot find the decryptor; no construction site" | The site is `dcf → dcg`, reachable by scanning for **direct `E8` calls** to the `dc*` cluster. The earlier scan only looked for `RijndaelManaged`/`Aes.Create` ctors, and `dcg` instantiates `AesCryptoServiceProvider` — a site that *was* found but misread. |
| "`dcg` is inert — sets `BlockSize=256`, CNG rejects it" | **Two errors.** The `0x100` goes to `set_KeySize` (AES-256), not `set_BlockSize` (`0x80` = 128). `dcg` is fully live. Slots are resolved via `SymmetricAlgorithm`'s vtable: `0x238`=`set_KeySize`, `0x1a8`=`set_BlockSize`, `0x1f8`=`set_Key`, `0x1d8`=`set_IV`, `0x258`=`set_Mode`, `0x278`=`set_Padding`. |
| "`svk`–`svr` are dismissed, not key material" | **They are the cipher.** `svq`/`svr` are the mask tables; `svk`/`svl`, `svm`/`svn` and `svo`/`svp` are three alternative chart key/IV pairs. |
| "16-byte constant header" — `ct₁ ⊕ ct₂` is zero for bytes 0–15 | **Not reproducible.** Conflict and Rebind use the *same* key pair yet differ from byte 0. The earlier observation must have compared two charts sharing both key and a plaintext preamble. |

**Why the ~2.7 M-key sweep failed:** it searched the wrong key space (`rjn`/`bundleCryptKey`
derivations) and, crucially, tested AES directly against the ciphertext — without the
stage-1 mask, no key can ever produce `EZFF`.

**Resolution of an earlier open item:** the sibling statics `svk`/`svl` and `svm`/`svn`
are **not** guarding a different payload type (as §3.3 previously speculated) — they are
alternative chart keys. Its corollary is that a decryptor which hardcodes one pair will
silently produce garbage for a chart that uses another, so always validate.

**Still open:** what selects the pair is not understood. All three are in wide use — across
the archive, 62 songs carry a `svk`/`svl` chart, 52 a `svm`/`svn` and 57 a `svo`/`svp` — and
**8 songs use more than one pair across their variants** (kamui uses all three), so it is
not even a per-song property. It looks like an authoring/build-time choice rather than
anything in the payload, the CDN path or `bundleCryptKey`.

### 3.4 MITM oracle — `tools/mitm/_cdn_rewrite.py`

A mitmdump addon that captures every `ez2game.co.kr` body under `mitm_live/` and can
rewrite CDN bodies on the fly via `_rewrite.json` (`op`: `none`/`zero16`/`zero32`/
`trunc16`/`trunc32`/`zeros`, plus `offset` and URL `match`). The config is re-read per
response, so experiments need no restart.

> If a rewrite hangs the loader, set `{"op":"none"}` and retry — nothing persists.
