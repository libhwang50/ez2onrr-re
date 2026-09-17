#!/usr/bin/env python3
"""
EZ2ON REBOOT: R - Offline AssetBundle Decryptor
Decrypts AssetBundles using the verified 1,024-byte XOR key (true_key_1024.bin).
Produces 100% valid UnityFS headers with intact size metadata for AssetRipper / UnityPy.
"""

import os
import sys
import argparse

PACKS_DIRS = [
    "EZ2ON REBOOT R/EZ2ON_Data/StreamingAssets/Packs/01",
    "EZ2ON REBOOT R/EZ2ON_Data/StreamingAssets/Packs/02"
]
OUTPUT_DIR = "EZ2ON REBOOT R/decrypted_bundles"
KEY_PATH = "EZ2ON REBOOT R/true_key_1024.bin"

def load_key():
    if not os.path.exists(KEY_PATH):
        print(f"[!] Master XOR key missing at {KEY_PATH}!")
        sys.exit(1)

    with open(KEY_PATH, "rb") as f:
        key = f.read(1024)

    if len(key) < 1024:
        print("[!] Key file must be at least 1,024 bytes.")
        sys.exit(1)

    return key

def decrypt_file(src_path, key, out_dir):
    fname = os.path.basename(src_path)
    out_path = os.path.join(out_dir, f"{fname}.unity3d")

    with open(src_path, "rb") as f:
        head = f.read(1024)
        rest = f.read()

    if head.startswith(b"UnityFS"):
        dec_head = head
    else:
        dec_head = bytes(a ^ b for a, b in zip(head, key))

    if not dec_head.startswith(b"UnityFS"):
        print(f"[!] Warning: {fname} did not produce valid UnityFS header!")
        return False

    with open(out_path, "wb") as f_out:
        f_out.write(dec_head)
        f_out.write(rest)

    print(f"[+] Decrypted: {fname} -> {out_path} ({os.path.getsize(out_path)} bytes)")
    return True

def main():
    parser = argparse.ArgumentParser(description="Decrypt EZ2ON REBOOT: R AssetBundles using master key")
    parser.add_argument("--limit", "-l", type=int, default=5, help="Number of files to decrypt (default: 5, set to 0 for all)")
    parser.add_argument("files", nargs="*", help="Specific bundle file paths to decrypt")
    args = parser.parse_args()

    key = load_key()
    print("[+] Loaded master 1,024-byte XOR decryption key.")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    if args.files:
        for fpath in args.files:
            decrypt_file(fpath, key, OUTPUT_DIR)
        return

    count = 0
    limit = args.limit

    for pdir in PACKS_DIRS:
        if not os.path.exists(pdir):
            continue

        files = os.listdir(pdir)
        for fname in files:
            src_path = os.path.join(pdir, fname)
            if decrypt_file(src_path, key, OUTPUT_DIR):
                count += 1
            if limit > 0 and count >= limit:
                print(f"\n[+] Reached limit of {limit} files. Stopping.")
                return

    print(f"\n[+] Complete! Successfully decrypted {count} bundles to '{OUTPUT_DIR}/'.")

if __name__ == "__main__":
    main()
