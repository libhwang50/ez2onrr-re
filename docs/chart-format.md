# 3.5 .ez/.ezi format & 3.6 tick→seconds

> Part of the EZ2ON REBOOT:R technical report — index: [docs/README.md](README.md).

* **`.ez` = note chart**: magic `EZFF`, version byte at `0x05` (observed `0x08`), `0x06–0x45`
  internal name (NUL-terminated), `0x86` ticks/measure (observed `0xC0`), **`0x88` initial
  BPM (float)**, `0x8C` track count (u16), `0x8E` total ticks (u32), `0x92` other BPM
  (float); `EZTR` per-track blocks follow, `count == track count`.
  Reference sample — Conflict: `4-shd`, BPM 160.0, 64 tracks, 19,680 ticks, 64 `EZTR`.
* **`.ezi` = keysound index, and it is TEXT**: `[index] [velocity] [filename]` per line,
  `\r\n` terminated, velocity 0/1, PKCS7-padded at EOF. Corroboration — MilK: 18,192 B ÷
  807 keysounds = **22.5 B per line**; Conflict: 2,719 lines, mapping verified against the
  game's parsed `instrumentDic` 2719/2719.
* **The `.ezi` is usually per song — but not always.** On the songs sampled while working
  out the format (Conflict 1/4, 1/3, 3/3; Engine 1/4, 3/3 and two gamemodes; Destr0yer
  1/4, 3/3; PUPA 5K HD vs NM; Hyper Magic 4K SHD vs 8K EZ) each decrypted `.ezi` was
  **byte-identical**, so it looked like a pure property of the song. **The one song we
  eventually captured all 16 variants of breaks that: `ultimatum` has two `.ezi`s, split
  by keymode — `{4K, 6K}` share one and `{5K, 8K}` share the other** (both 62,512 B, same
  length, different bytes). *(Supersedes "one sha256 per song, even across key modes", and
  with it the claim that no key mode ever needs a fresh keysound set.)* Consequence: a
  chart's `.ez` only means anything next to **its own** `.ezi` — the two must be captured
  and served as a pair. Every `charts.json` record is one capture, so pairs stay matched;
  the risk is only cross-variant fallbacks, which is why `chart any` now stays inside the
  requested `gamemode`.
* **The `.ez` chart differs by keymode and difficulty — but only in how notes are ASSIGNED,
  not in what sounds.** Comparing the multiset of `(position, keysound)` over *all* tracks:
  * Conflict **4K EZ ⊂ 4K SHD** — 6386 events, none unique to EZ; SHD has 7 extra;
  * Conflict 4K HD is likewise a strict **subset** of 4K SHD (7 dropped, 0 added);
  * PUPA 5K HD vs 5K NM — **identical**, 4047 events each, and the two render to
    **byte-identical audio**;
  * Hyper Magic 4K SHD vs 8K EZ differ by 3 events out of 2506.

  Meanwhile the lane counts move enormously — Conflict's lanes hold 330 notes on EZ, 1304
  on HD and 1814 on SHD, while the total stays ~6390. So difficulty moves notes between the
  player's lanes and the auto-played tracks; the *song* is essentially unchanged.
  **Practical consequence: one chart per song is enough to render the full song** (each
chart record pairs its own `.ez` with its own `.ezi`, so a render is always internally
consistent; only the *lane count* of the variant you get may differ from the one you
selected).
* **Song-select and in-game commands** (from the same page, and the basis of
  `server/re/_sweep.py`): in song select `0`–`9` jump to a list section, `PageUp`/`PageDown`
  move 8 rows, `a`–`z` jump to songs starting with that letter (leading articles are
  ignored, so *The Ashtray* is under `A`), `F6` picks randomly, `Up`/`Down` moves the song
  selection, `Left`/`Right` the difficulty, and `TAB` cycles the key mode (4B/5B/6B/8B) —
  which is exactly what a capture sweep needs to vary a variant. (Confirmed in game: the
  bottom hint bar's icons for the two arrow pairs read the wrong way round.) During play `F7`/`F8` nudge display sync ±1 ms,
  `F9`/`F10` halve/double note speed. `Enter` is 결정 (confirm, and starts a song — the
  pause screen's hint bar shows it; the song select's shows `SHIFT`). Leaving a running song
  is `Esc` → `Up` (the focus wraps to the bottom button) → `Enter` (MUSIC SELECT), which is
  how a capture sweep abandons each song instead of playing it. `re/_sweep.py --calibrate`
  derives the difficulty/keymode keys empirically, because the request JSON names both.
* **The Lounge is a stats hub; its MUSIC VIDEO tab is a chart-harvesting route.** The
  Lounge screen is tabbed **PROFILE / PLAYINFO / RECENT / RANKING / MUSIC VIDEO**. The
  BGA-watching route a capture confirmed is its **MUSIC VIDEO** tab: it goes through the same
  `c2s_get_pattern_file` flow and serves the song's **4K EZ** chart (the Lounge chart for
  Conflict was `4-ez` with an `.ezi` byte-identical to Conflict's), so charts can be collected
  by browsing BGAs with no gameplay, and per the point above those 4K EZ charts are enough to
  render a song. Symmetrically, its **RANKING** tab is where the rank-server traffic comes
  from — see §3.7.

* **The `.ez` per-track counts differ by keymode and difficulty** (Conflict SHD vs HD differs
  in the lanes *and* in nearly every track 23–63, while the track-22 `MR` note is the same).
  It is the track *assignment* that moves, per the point above.
* **Key mode is directly readable from the chart**: the number of playable lanes is the
  count of tracks from 3 upwards that carry notes — 4 → 4K (API keymode `1`), 5 → 5K,
  6 → 6K (API keymode `3`), 8 → 8K. Confirmed on all four. 7K is unobserved (it is said to
  be course-only, behind the O2Jam Collaboration DLC).
* **Difficulty is `levelmode`: 1=EZ, 2=NM, 3=HD, 4=SHD** (Conflict and Engine at levelmode 4
  are both SHD; Conflict levelmode 3 is HD).
* **`gamemode` is BASIC (1) vs STANDARD (2), and it IS a chart selector — for some songs**
  *(supersedes the earlier "gamemode 1 and 2 produced identical charts, so it is not a
  chart selector", which held only for the songs sampled)*. The two modes are otherwise
  identical (controls, play style, judgement *names*, scoring to 1.1 M, multiplayer); BASIC
  is the more forgiving one:
  * **KOOL base window: 40 ms in BASIC vs 22 ms in STANDARD** (≈2× more lenient), and the
    groove gauge is far more generous;
  * **replacement rule**: where the STANDARD chart is level ≥6 (4K), ≥8 (5K/6K) or ≥11 (DLC),
    its **EZ~NM** patterns are swapped for easier BASIC-exclusive ones. HD/SHD are not
    replaced, and there are named exceptions (Mystic Dream 9903 Horror Mix, 바람에게 부탁해
    5K, TYR, METATRON 6K). Max 4 keymodes × 4 difficulties = 16 patterns per song;
  * Sudden Death is not playable in BASIC; 8K BASIC was added 2023-04-20; BASIC got its own
    rating system on 2025-12-29 (relevant to the rank work — the myinfo rating may be
    per-mode for the same reason the rating appears to be).
  Consequence for the private server and for capture: **record `gamemode` with every chart
  capture** and prefer the exact one when serving (`gamemode` is in the request JSON, so a
  capture run records it for free). Source: NamuWiki "EZ2ON REBOOT : R/시스템" §4.1–4.2.
* **The capture addon can also *capture*.** With `cdn` in the passthrough list (what
  `re/_exp.py harvest` sets) a CDN cache miss is forwarded to the official CDN and the body is
  filed into `extracted_charts/<song>/<km>/<diff>/` in exactly `ripper/dump_song.py`'s layout
  (`cdn_ez_cap.bin`, `cdn_ezi_cap.bin`, an `ident.json` with the URLs and label, and the
  decrypted `.ez`/`.ezi`, plus an `instrumentDic.json` derived from the `.ezi`, when the
  key pair validates — `ripper/decrypt_chart.py --archive` backfills any of that which is missing).
  **The decrypt step is backend-agnostic on purpose**: `ripper/decrypt_chart.py` used to import
  pycryptodome only, which the *system* python running mitmdump does not have, and a bare
  `except` in the capture addon hid the ImportError — so captures filed the ciphertext and silently
  skipped the plaintext. That makes the archive the single
  source of truth — `_build_data.py` is still the only translator — and turns a whole song
  sweep into coverage with no extra tooling. Without the knob a miss is a 404 and no
  game-host request leaves the machine.
* **The CDN URL hash is not a content hash.** A song's `.ezi` URL differs per variant while
  the decrypted bytes are identical, so the path segment cannot be used to identify
  content — match on the decrypted payload instead.
* **Positions are ticks; the game works in measures.** `InGameCore` divides by
  `ticksPerMeasure` (Conflict: 192), so `normalNoteData[*].seu` is measures and
  `<set>k__BackingField` is seconds (`seu × 60/BPM × 4`). Cross-check: the first 1P Key1
  note is tick 384 = measure 2.0 = keysound 166, matching the game's `{seu: 2.0, sev: 166}`.
* **Note record = 13 bytes** (the v7 sizing) for both v7 and v8: `pos`(u32), `type`(u8),
  then 8 param bytes. Type 1 uses `keysound`(u16), `velocity`(u8, 127 in practice),
  `pan`(u8, 64 = centre), pad, a 2-byte field at `params[5:7]`, pad. Types 2/3/4 are
  volume (u8), BPM (float), beats-per-measure (u8).
* **The v8 anti-tamper step does NOT apply to CDN-served charts.** `ezunfn` (subtract
  `0xF9` at `0x1F8`/`0x400`/`0x5F0` every `0x600`) is documented for arcade v8 files, but
  running it on a decrypted REBOOT payload *introduces* 38 non-monotonic positions, 67
  out-of-range positions and 4 invalid keysound indices, whereas the file as served has
  **zero** of each. Adding `0xF9` turns valid note types (`0x01`) into `0xFA`. Do not apply it.
* **Track index → lane, and long notes — SOLVED for 4K.** Verified against the game's own
  `normalLanes` over 3 songs x 4 lanes, 12/12 exact:
  * **tracks 3–6 are the 4K lanes, in order** (track 3 → lane 0 … track 6 → lane 3);
  * a type-1 note is a **long note iff `flags not in (0, 6)`**; `flags` is the uint16 at
    `params[5:7]`. Normal + long per lane reproduced `normalLanes` exactly.
  **`flags` is the hold length in ticks.** Confirmed against the charts: with that unit every
  hold ends at or before the next note in its own lane (43/43 in Changa 2, 83/83 in Rebind),
  whereas at twice that unit most holds would overlap the next note in the same lane, which a
  lane cannot do. Values are multiples of 12 ticks (a 1/16-measure grid), giving holds of
  0.2-2.6 s, and `bar`/`hold` land on plausible musical positions. It has **no audio effect**:
  verified in-game that a long note's keysound plays exactly like a normal note's and is not
  sustained. So it drives judgement and the visual hold bar, and `ripper/visualize_song.py` uses it to
  keep a lane lit for the whole hold.
* **A late key press starts the keysound from the middle, not from its start** (reported
  in-game: missing the first tick of a long note and pressing after it). So the game plays the
  sample from an offset derived from ticks-elapsed-since-the-note-position. A renderer that
  always restarts each keysound at 0 therefore matches a *correct* keypress, not a late one —
  worth remembering when comparing a render against a sloppy play-through.
* **`name` at `0x06` is the chart variant, not the song name**: it is `<keys>-<difficulty>`, e.g.
  `4-shd`, `8-ez`, `5-nm`, `5-hd`. So it decodes the key mode **and** difficulty straight
  from the chart, which is more direct than asking the API. It is not always set — Engine
  and Revelation leave it empty — and `#PTMAKE` marks a chart built with the in-game
  pattern maker. Different songs genuinely share a tag: Conflict and Hyper Magic both
  carry `4-shd` because both are 4K SHD.
* **Key mode from the lane count**, which matches the name tag on every sample: 4 lanes →
  4K, 5 → 5K, 6 → 6K, 8 → 8K. (7K is unobserved; it is said to be course-only.) This is
  the fallback when the name is empty or `#PTMAKE`.
* **Track 22 triggers a supplementary `MR` layer, not the full song.** Every one of the 5
  captured songs holds a single type-1 note there (positions 0, 96 or 192 ticks).
  **Do not mistake it for the song** — per listening, it contains only the instruments too
  long or too incidental to sample as keysounds. Rebind's `MR` is ambience alone. Its
  filename varies (`00-MR.wav`, `MR.wav`, `99-BG.wav`, and for `ae_illusion`
  `mrt22Fix.wav` = "MR, track 22, fixed"), so resolve it from the chart:
  `ripper/parse_chart.py --backing --ezi f.ezi f.ez`.
* **The song is a render of the chart.** Playing every type-1 note on every track, each
  keysound at its scheduled time, reconstructs it. Tracks 3–6 are the player's lane input
  and 23–63 are auto-played instrument layers; the split does not matter for rendering —
  all of them sound. **Verified by ear against gameplay — reported as an exact match.**
* **Player vs auto is exactly `tracks 3 .. 3+lane_count-1`.** On all 12 captured charts the
  tracks carrying keysounds from 3 upward are that contiguous run and nothing else: 3–6 for
  4K, 3–8 for 6K, 3–10 for 8K. Everything from track 22 (the MR layer) and 23+ is
  auto-played. So `Chart.lane_count` is the rule, and a fixed `range(3, 22)` is only safe
  because no chart yet places a note in the unused 7–21 gap. `ripper/visualize_song.py` uses it to
  dim the auto rows (see §5).
* **One note triggers exactly one keysound.** The 13-byte record has room for a single u16
  index at `params[0:2]`; a byte census over all 32,923 type-1 notes shows `params[4]`
  non-zero exactly once and `params[7]` never, so there is no hidden second index. The pan
  byte (`params[3]`) confirms it: the rare same-keysound-at-the-same-tick cases (hypermagic
  1, kamui 2) are two *independent* notes with different `pan` that share a sample, not one
  note emitting two sounds. A per-keysound row therefore maps 1:1 to a note.
* **Nearly — but not quite — every declared keysound is played.** `declared-but-unplayed` is
  0 for conflict/rebind/suddendeath, but is **72 for ultimatum**, 3 for destr0yer and 1 each
  for changemyworld and hypermagic. Two charts also have a *used-but-undeclared* index, always
  a **track-22 placeholder** (index `0` in changa2, `255` in kamui) — the `MR` track pointing
  at an empty slot. These render as `(unknown)` rows.

### 3.6 Tick → seconds (validated)

```
seconds = ticks * 1.25 / BPM          # piecewise, at each BPM change
```

A measure is **always 4 beats of 48 ticks**, and `ticksPerMeasure` is always 192. So a
measure lasts `4 * 60 / BPM` seconds and one tick `60 / (BPM * 48)`.

**`beatsPerMeasure` (type 4/5 events) does NOT change timing** — it is visual/metrical only.
This matters: Conflict has a 4→7 change at tick 11136 and back to 4 at 14832, which makes
the difference between 175.41 s and 153.75 s.

| song | model | BGA video |
|---|---|---|
| Rebind | 162.58 s | 162.67 s |
| Conflict | 153.75 s | 154.47 s |

Both videos run slightly longer than the chart, consistent with a lead-out. Treating the
time-signature change as a real tempo change would be off by 21 s on Conflict.

`Chart.seconds_at(tick)` and `Chart.note_seconds()` in `ripper/parse_chart.py` implement this, and
`ripper/render_song.py` uses it to mix every note's keysound into an audio file, and
`ripper/visualize_song.py` draws that mix as a video with the keysounds overlaid on the BGA. All 5 captured
songs render; Conflict (6393 events, 2719 distinct keysounds) takes ~3 s and comes out
with a normal mix profile (mean ≈ −17 dB, normalised peak). Rendering is fast enough to do
in bulk — 5 songs in 11 s (`ripper/render_song.py --all`).
* **Open: note types 5/6/9** (and 8 in some files) are undocumented; the reference
  `ezinfo` reports them as unhandled. Exposed raw by `ripper/parse_chart.py`.
