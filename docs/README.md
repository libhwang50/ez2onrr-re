# EZ2ON REBOOT:R — technical report

The reverse-engineering write-up, split by topic. **Section numbers (`§3.1`,
`§7.6`, …) are stable** and used for cross-references across the repo — a bare
`§x.y` resolves here.

| § | document | contents |
|---|---|---|
| 1 | [environment.md](environment.md) | game build, runtime, ground rules (read-only, crash hazards) |
| 2 | [assets.md](assets.md) | AssetBundle encryption, keysounds, BGA |
| 3 | [charts.md](charts.md) | chart delivery overview, the API session cipher (§3.1), DTOs and keys (§3.2) |
| 3.3 | [chart-cipher.md](chart-cipher.md) | the CDN payload cipher, and the MITM rewrite oracle (§3.4) |
| 3.5 | [chart-format.md](chart-format.md) | `.ez`/`.ezi` format, lanes, long notes, tick→seconds (§3.6) |
| 3.7 | [rank.md](rank.md) | rank host, leaderboards, score upload, the 8CN26 watchdog |
| 4 | [runtime.md](runtime.md) | managed invocation, `da.rus`, offsets, code scanning, metadata |
| 5 | [tools.md](tools.md) | the tool inventory |
| 6 | [outputs.md](outputs.md) | where captures land |
| 7 | [status.md](status.md) | what is done, what is next |

Guides outside this directory:

| guide | |
|---|---|
| [`../README.md`](../README.md) | user-facing: ripping assets, charts and rendering |
| [`../server/README.md`](../server/README.md) | the private server — running, Docker, identity, offline recipe |
| [`../client/README.md`](../client/README.md) | the Frida-free patcher, and Goldberg for players with no Steam account |
| [`../tools/README.md`](../tools/README.md) | the reverse-engineering harness |
