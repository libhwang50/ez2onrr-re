#!/usr/bin/env python3
"""
EZ2ON REBOOT: R - Song Bundle Finder & Indexer
Maps encrypted AssetBundle file hashes to song IDs/codenames (e.g. rebind, ae_illusion, devote).
Distinguishes between Audio (keysounds) and Video (BGA) bundles.
Supports searching, indexing, and on-demand decryption.
"""

import os
import sys
import io
import re
import json
import argparse

KEY_PATH = "EZ2ON REBOOT R/true_key_1024.bin"
PACKS_DIRS = [
    "EZ2ON REBOOT R/EZ2ON_Data/StreamingAssets/Packs/01",
    "EZ2ON REBOOT R/EZ2ON_Data/StreamingAssets/Packs/02"
]
OUTPUT_DIR = "EZ2ON REBOOT R/decrypted_bundles"
INDEX_CACHE = "song_index.json"

def load_key():
    if not os.path.exists(KEY_PATH):
        print(f"[!] Master XOR key missing at {KEY_PATH}!")
        sys.exit(1)
    with open(KEY_PATH, "rb") as f:
        return f.read(1024)

def identify_song_id(fpath, key):
    import UnityPy
    with open(fpath, "rb") as f:
        head = f.read(1024)
        rest = f.read()

    dec_head = head if head.startswith(b"UnityFS") else bytes(a ^ b for a, b in zip(head, key))
    buf = io.BytesIO(dec_head + rest)

    try:
        env = UnityPy.load(buf)
        paths = list(env.container.keys())
        song_id = "unknown"
        asset_type = "unknown"

        for p in paths:
            m = re.search(r"music/(audios|videos)/([^/.]+)", p, re.IGNORECASE)
            if m:
                cat = m.group(1).lower()
                song_id = m.group(2).lower()
                asset_type = "video" if cat == "videos" or p.endswith(".mp4") else "audio"
                break

        if song_id == "unknown":
            for obj in env.objects:
                if obj.type.name == "VideoClip":
                    data = obj.read()
                    orig = getattr(data, "m_OriginalPath", "")
                    m_vid = re.search(r"music/videos/([^/.]+)", orig, re.IGNORECASE)
                    if m_vid:
                        song_id = m_vid.group(1).lower()
                        asset_type = "video"
                        break

        return song_id, asset_type, len(paths), paths[:3]
    except Exception as e:
        return f"error_{e}", "unknown", 0, []

def build_index(key, force=False):
    if not force and os.path.exists(INDEX_CACHE):
        with open(INDEX_CACHE, "r") as f:
            print(f"[+] Loaded existing index from '{INDEX_CACHE}'.")
            return json.load(f)

    print("[*] Building song bundle index from Packs/01 and Packs/02...")
    index = {}

    total = 0
    for pdir in PACKS_DIRS:
        if not os.path.exists(pdir):
            continue
        pack_name = os.path.basename(pdir)
        files = os.listdir(pdir)
        print(f"[*] Scanning {len(files)} files in Pack {pack_name}...")

        for fname in files:
            fpath = os.path.join(pdir, fname)
            song_id, asset_type, asset_count, sample_paths = identify_song_id(fpath, key)
            total += 1

            index[fname] = {
                "song_id": song_id,
                "asset_type": asset_type,
                "pack": pack_name,
                "path": fpath,
                "size_bytes": os.path.getsize(fpath),
                "asset_count": asset_count,
                "sample_assets": sample_paths
            }
            if total % 100 == 0:
                print(f"    Indexed {total} bundles...")

    with open(INDEX_CACHE, "w") as f:
        json.dump(index, f, indent=2)

    print(f"\n[+] Successfully indexed {len(index)} bundles -> saved to '{INDEX_CACHE}'.")
    return index

def decrypt_bundle(src_path, key, out_dir):
    fname = os.path.basename(src_path)
    out_path = os.path.join(out_dir, f"{fname}.unity3d")
    os.makedirs(out_dir, exist_ok=True)

    with open(src_path, "rb") as f:
        head = f.read(1024)
        rest = f.read()

    dec_head = head if head.startswith(b"UnityFS") else bytes(a ^ b for a, b in zip(head, key))

    with open(out_path, "wb") as f_out:
        f_out.write(dec_head)
        f_out.write(rest)

    print(f"[+] Decrypted bundle saved to: {out_path} ({os.path.getsize(out_path)} bytes)")
    return out_path

def main():
    parser = argparse.ArgumentParser(description="Find & Index EZ2ON REBOOT: R Song Bundles")
    parser.add_argument("query", nargs="?", help="Song ID or keyword to search (e.g. rebind, ae_illusion, devote)")
    parser.add_argument("--index", "-i", action="store_true", help="Force rebuild of song_index.json")
    parser.add_argument("--decrypt", "-d", action="store_true", help="Decrypt matching song bundle(s) to decrypted_bundles/")
    args = parser.parse_args()

    key = load_key()

    if args.index:
        index = build_index(key, force=True)
        if not args.query:
            return

    if not os.path.exists(INDEX_CACHE):
        index = build_index(key, force=False)
    else:
        with open(INDEX_CACHE, "r") as f:
            index = json.load(f)

    if not args.query:
        print("[!] Please specify a song ID or keyword to search.")
        print("Example: python3 find_bundle.py rebind")
        print(f"Total indexed bundles: {len(index)}")
        return

    q = args.query.lower()
    matches = []

    for fname, data in index.items():
        if q == data["song_id"] or q in data["song_id"] or q in fname:
            matches.append((fname, data))

    if not matches:
        print(f"[!] No bundles found matching '{args.query}'.")
        return

    print(f"\n[+] Found {len(matches)} matching bundle(s) for '{args.query}':\n")
    for fname, data in matches:
        print(f"  Song ID     : {data['song_id']}")
        print(f"  Asset Type  : {data['asset_type'].upper()}")
        print(f"  Bundle Hash : {fname}")
        print(f"  Pack        : {data['pack']}")
        print(f"  Size        : {data['size_bytes'] / (1024*1024):.2f} MB")
        print(f"  Asset Count : {data['asset_count']}")
        if data['sample_assets']:
            print(f"  Sample Asset: {data['sample_assets'][0]}")
        print("-" * 60)

        if args.decrypt:
            decrypt_bundle(data['path'], key, OUTPUT_DIR)

if __name__ == "__main__":
    main()
