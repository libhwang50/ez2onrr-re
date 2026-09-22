#!/usr/bin/env python3
"""
EZ2ON REBOOT: R - Asset & Audio/BGA Extractor
Extracts raw FLAC/OGG/WAV audio files and BGA video (.mp4) files from AssetBundles.
Prevents UTF-8 corruption on TextAsset audio buffers and extracts VideoClip streams cleanly.
"""

import os
import io
import struct
import json
import argparse

import ez2lib

INDEX_CACHE = "song_index.json"
OUTPUT_DIR = "extracted_assets"

def extract_bundle_contents(fpath, key, out_folder, extract_bga=False):
    import UnityPy

    with open(fpath, "rb") as f:
        head = f.read(1024)
        rest = f.read()

    buf = io.BytesIO(ez2lib.decrypt_bundle_head(head, key) + rest)

    try:
        env = UnityPy.load(buf)
    except Exception as e:
        print(f"[!] Failed to parse bundle {os.path.basename(fpath)}: {e}")
        return 0, 0

    os.makedirs(out_folder, exist_ok=True)
    extracted_count = 0
    total_bytes = 0

    for obj in env.objects:
        if obj.type.name == "TextAsset":
            try:
                raw = obj.get_raw_data()
                name_len = struct.unpack("<I", raw[:4])[0]
                name = raw[4:4+name_len].decode("utf-8", errors="ignore")

                name_padded = (name_len + 3) & ~3
                script_off = 4 + name_padded
                script_len = struct.unpack("<I", raw[script_off:script_off+4])[0]
                script_bytes = raw[script_off+4 : script_off+4+script_len]

                out_file = os.path.join(out_folder, name)
                with open(out_file, "wb") as f_out:
                    f_out.write(script_bytes)

                extracted_count += 1
                total_bytes += len(script_bytes)
            except Exception as e:
                print(f"[!] Error extracting TextAsset object: {e}")

        elif obj.type.name == "AudioClip":
            try:
                data = obj.read()
                for samples_name, samples in data.samples.items():
                    out_file = os.path.join(out_folder, samples_name)
                    with open(out_file, "wb") as f_out:
                        f_out.write(samples)
                    extracted_count += 1
                    total_bytes += len(samples)
            except Exception as e:
                print(f"[!] Error extracting AudioClip object: {e}")

        elif obj.type.name == "VideoClip" and extract_bga:
            try:
                data = obj.read()
                orig_path = getattr(data, "m_OriginalPath", "")
                if orig_path:
                    base_name = os.path.basename(orig_path)
                else:
                    base_name = f"{getattr(data, 'm_Name', 'bga')}.mp4"

                ext_res = data.m_ExternalResources
                src = ext_res.m_Source
                base_src = os.path.basename(src)

                target_res = None
                for f_val in env.files.values():
                    if hasattr(f_val, "files"):
                        target_res = f_val.files.get(src) or f_val.files.get(base_src)
                        if target_res:
                            break

                if target_res:
                    target_res.Position = ext_res.m_Offset
                    video_bytes = target_res.read_bytes(ext_res.m_Size)
                    out_file = os.path.join(out_folder, base_name)
                    with open(out_file, "wb") as f_out:
                        f_out.write(video_bytes)

                    print(f"    [+] Extracted BGA Video: {base_name} ({len(video_bytes) / (1024*1024):.2f} MB)")
                    extracted_count += 1
                    total_bytes += len(video_bytes)
                else:
                    print(f"[!] Target resource '{base_src}' not found in bundle environment.")
            except Exception as e:
                print(f"[!] Error extracting VideoClip object: {e}")

    return extracted_count, total_bytes

def main():
    parser = argparse.ArgumentParser(description="Extract FLAC Audio & BGA Video Assets from EZ2ON REBOOT: R Bundles")
    parser.add_argument("query", help="Song ID, bundle hash, or file path (e.g. rebind, ae_illusion, devote)")
    parser.add_argument("--bga", "-b", action="store_true", help="Extract BGA video (.mp4) in addition to keysounds/audio")
    parser.add_argument("--output", "-o", default=OUTPUT_DIR, help="Output folder for extracted files")
    args = parser.parse_args()

    key = ez2lib.load_bundle_key()

    targets = []
    song_id = None

    if os.path.exists(args.query):
        targets.append(args.query)
        song_id = os.path.basename(args.query).split(".")[0]
    elif os.path.exists(INDEX_CACHE):
        with open(INDEX_CACHE, "r") as f:
            index = json.load(f)

        q = args.query.lower()
        for fname, data in index.items():
            if q == data["song_id"] or q in data["song_id"] or q in fname:
                if not args.bga and data.get("asset_type") == "video" and q != fname and q != data["song_id"]:
                    continue
                targets.append(data["path"])
                song_id = data["song_id"]

    if not targets:
        print(f"[!] Could not find bundle matching '{args.query}'.")
        return

    out_folder = os.path.join(args.output, song_id or "extracted")
    print(f"[*] Extracting assets for '{song_id}' ({len(targets)} bundle(s), BGA={args.bga})...")

    total_count = 0
    total_size = 0

    for target_path in targets:
        print(f"  -> Processing bundle: {os.path.basename(target_path)}")
        count, size = extract_bundle_contents(target_path, key, out_folder, extract_bga=args.bga)
        total_count += count
        total_size += size

    print(f"\n[+] SUCCESS! Extracted {total_count} files ({total_size / (1024*1024):.2f} MB) to '{out_folder}/'")

if __name__ == "__main__":
    main()
