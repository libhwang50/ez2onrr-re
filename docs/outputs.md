# 6. Outputs

> Part of the EZ2ON REBOOT:R technical report — index: [docs/README.md](README.md).

| Path | Contents |
|---|---|
| `extracted_assets/<song_id>/` | FLAC/OGG keysounds, BGA `.mp4` |
| `extracted_charts/<song>/<keymode>/<difficulty>/` | `ident.json` (identity + label + metadata), `cdn_*.bin`, `ez.ez` / `ezi.ezi` (decrypted), `mem_rjl/rjm/rjn.bin`, `instrumentDic.json`. Nesting so each variant keeps its own capture (`destr0yer/5k/hd/`); `--name-by title` merges variants into one directory and `--name-by id` uses the music id, and an unidentifiable song falls back to `song_<hash>` |
| `EZ2ON REBOOT R/decrypted_bundles/` | decrypted `.unity3d` containers |
| `song_index.json` | bundle-hash → song/asset index |
| `true_key_1024.bin` | master bundle XOR key |
| `server/data/` | generated locally by `server/_build_data.py` — decrypted API response templates, chart→CDN path map, profile overrides. **Git-ignored**: personal data, the music DB, and key material; regenerate from your own captures |
