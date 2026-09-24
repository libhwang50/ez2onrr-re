#!/usr/bin/env python3
"""Shared helpers for the EZ2ON REBOOT: R ripper CLIs.

This is an internal module, not a user-facing tool. It holds the few facts several
tools have to agree on, so they are defined once:

* where the repository and its master bundle key live (``load_bundle_key``);
* how an AssetBundle header is decrypted (``decrypt_bundle_head``);
* how a capture's label dictionary is read back (``chart_label``).

Importing this module has no side effects and no third-party dependencies, so the
Frida/crypto-heavy tools can import it freely.
"""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root (this file lives in ripper/)

GAME_DIR = os.path.join(ROOT, "EZ2ON REBOOT R")
BUNDLE_OUT = os.path.join(GAME_DIR, "decrypted_bundles")
BUNDLE_KEY_NAME = "true_key_1024.bin"

# The README puts the master key in the repository root. Older setups also kept a
# copy inside the game directory (the two tools that predate this module looked
# only there), so accept either, root first.
BUNDLE_KEY_PATHS = (
    os.path.join(ROOT, BUNDLE_KEY_NAME),
    os.path.join(GAME_DIR, BUNDLE_KEY_NAME),
)

#: The pack directories that hold the encrypted AssetBundles, relative to the repo.
PACKS_DIRS = (
    os.path.join(GAME_DIR, "EZ2ON_Data", "StreamingAssets", "Packs", "01"),
    os.path.join(GAME_DIR, "EZ2ON_Data", "StreamingAssets", "Packs", "02"),
)


def bundle_key_path() -> str:
    """Where the master bundle key is, preferring the repo root."""
    for path in BUNDLE_KEY_PATHS:
        if os.path.exists(path):
            return path
    return BUNDLE_KEY_PATHS[0]


def load_bundle_key() -> bytes:
    """Read the 1,024-byte master bundle XOR key, or exit with a clear message."""
    path = bundle_key_path()
    if not os.path.exists(path):
        sys.exit("[!] Master XOR key missing: expected %s (derive it once with "
                 "ripper/harvest_key.py, with the game running)" % path)
    with open(path, "rb") as f:
        key = f.read(1024)
    if len(key) < 1024:
        sys.exit("[!] %s must be at least 1,024 bytes (got %d)" % (path, len(key)))
    return key


def decrypt_bundle_head(head: bytes, key: bytes) -> bytes:
    """Decrypt the first 1,024 bytes of a bundle. A plaintext ``UnityFS`` is left alone."""
    if head.startswith(b"UnityFS"):
        return head
    return bytes(a ^ b for a, b in zip(head, key))


def chart_label(song_dir: str) -> dict:
    """The label dict ``ripper/dump_song.py`` wrote next to a capture, if present.

    Returns ``{}`` when ``ident.json`` is missing or malformed, so callers can treat
    "no label" and "bad label" the same way.
    """
    try:
        return (json.load(open(os.path.join(song_dir, "ident.json"))) or {}).get("label") or {}
    except (OSError, ValueError):
        return {}
