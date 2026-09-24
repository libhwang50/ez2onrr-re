# 2. AssetBundles

> Part of the EZ2ON REBOOT:R technical report — index: [docs/README.md](README.md).

* Every bundle's **first 1,024 bytes (0x400)** are XOR-encrypted with a static keystream;
  **offset 0x400+ is plaintext** LZ4/LZMA Unity data.
* Master key `true_key_1024.bin` =
  `RAM_decrypted_header[0:1024] XOR disk_header[0:1024]`, harvested zero-hook with
  `ripper/harvest_key.py`.
* With that key every bundle decrypts to a valid `UnityFS` container
  (`ripper/find_bundle.py`, `ripper/extract_assets.py`).
* **Audio / BGA extraction** (`ripper/extract_assets.py`) parses raw C++ object bytes directly —
  AssetRipper's UTF-8 path corrupts binary `.bytes`. `TextAsset` → FLAC/OGG keysounds;
  `VideoClip.m_ExternalResources` → 720p H.264 `.mp4`.
