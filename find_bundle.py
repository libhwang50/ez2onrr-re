#!/usr/bin/env python3
"""EZ2ON REBOOT: R - Song Bundle Finder, Indexer & Decryptor

Maps encrypted AssetBundle file hashes to song IDs/codenames (e.g. rebind,
ae_illusion, devote), and distinguishes Audio (keysounds) from Video (BGA)
bundles. Supports searching, indexing, bulk decryption and on-demand decryption.

Usage
-----
    python3 find_bundle.py rebind                 # find a song's bundles
    python3 find_bundle.py --index                # rebuild song_index.json
    python3 find_bundle.py rebind --decrypt       # decrypt the matches
    python3 find_bundle.py --decrypt-all          # decrypt the first 5 bundles
    python3 find_bundle.py --decrypt-all --limit 0  # decrypt every bundle

Decryption is a no-op on a bundle that is already plaintext, so re-running is safe.
"""
import argparse
import io
import json
import os
import re

import ez2lib

INDEX_CACHE = "song_index.json"


def identify_song_id(fpath, key):
    import UnityPy

    with open(fpath, "rb") as f:
        head = f.read(1024)
        rest = f.read()

    buf = io.BytesIO(ez2lib.decrypt_bundle_head(head, key) + rest)

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
    for pdir in ez2lib.PACKS_DIRS:
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
                "sample_assets": sample_paths,
            }
            if total % 100 == 0:
                print(f"    Indexed {total} bundles...")

    with open(INDEX_CACHE, "w") as f:
        json.dump(index, f, indent=2)

    print(f"\n[+] Successfully indexed {len(index)} bundles -> saved to '{INDEX_CACHE}'.")
    return index


def decrypt_bundle(src_path, key, out_dir):
    """Decrypt one bundle's 1,024-byte header, writing <name>.unity3d. True on success."""
    fname = os.path.basename(src_path)
    out_path = os.path.join(out_dir, f"{fname}.unity3d")
    os.makedirs(out_dir, exist_ok=True)

    with open(src_path, "rb") as f:
        head = f.read(1024)
        rest = f.read()

    dec_head = ez2lib.decrypt_bundle_head(head, key)
    ok = dec_head.startswith(b"UnityFS")
    if not ok:
        print(f"[!] Warning: {fname} did not produce a valid UnityFS header!")

    with open(out_path, "wb") as f_out:
        f_out.write(dec_head)
        f_out.write(rest)

    print(f"[+] Decrypted: {fname} -> {out_path} ({os.path.getsize(out_path)} bytes)")
    return ok


def decrypt_all(key, limit):
    """Bulk-decrypt the pack directories. `limit` <= 0 means every bundle."""
    count = 0
    for pdir in ez2lib.PACKS_DIRS:
        if not os.path.exists(pdir):
            continue
        for fname in sorted(os.listdir(pdir)):
            if decrypt_bundle(os.path.join(pdir, fname), key, ez2lib.BUNDLE_OUT):
                count += 1
            if limit > 0 and count >= limit:
                print(f"\n[+] Reached limit of {limit} files. Stopping.")
                return count
    print(f"\n[+] Complete! Decrypted {count} bundle(s) to '{ez2lib.BUNDLE_OUT}/'.")
    return count


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("query", nargs="?", help="Song ID or keyword to search (e.g. rebind, ae_illusion, devote)")
    parser.add_argument("--index", "-i", action="store_true", help="Force rebuild of song_index.json")
    parser.add_argument("--decrypt", "-d", action="store_true", help="Decrypt matching song bundle(s)")
    parser.add_argument("--decrypt-all", "-a", action="store_true",
                        help="Decrypt bundles from the pack directories (see --limit)")
    parser.add_argument("--limit", "-l", type=int, default=5,
                        help="With --decrypt-all: how many to decrypt (default 5, 0 = all)")
    args = parser.parse_args()

    key = ez2lib.load_bundle_key()

    if args.decrypt_all:
        decrypt_all(key, args.limit)
        if not args.query and not args.index:
            return

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
    matches = [
        (fname, data)
        for fname, data in index.items()
        if q == data["song_id"] or q in data["song_id"] or q in fname
    ]

    if not matches:
        print(f"[!] No bundles found matching '{args.query}'.")
        return

    print(f"\n[+] Found {len(matches)} matching bundle(s) for '{args.query}':\n")
    for fname, data in matches:
        print(f"  Song ID     : {data['song_id']}")
        print(f"  Asset Type  : {data['asset_type'].upper()}")
        print(f"  Bundle Hash : {fname}")
        print(f"  Pack        : {data['pack']}")
        print(f"  Size        : {data['size_bytes'] / (1024 * 1024):.2f} MB")
        print(f"  Asset Count : {data['asset_count']}")
        if data["sample_assets"]:
            print(f"  Sample Asset: {data['sample_assets'][0]}")
        print("-" * 60)

        if args.decrypt:
            decrypt_bundle(data["path"], key, ez2lib.BUNDLE_OUT)


if __name__ == "__main__":
    main()
