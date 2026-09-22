#!/usr/bin/env python3
"""Derive the master bundle XOR key (`true_key_1024.bin`) from live game memory.

The first 1,024 bytes of every AssetBundle are XOR-encrypted with one static
keystream; everything after is plaintext. With the game running (a bundle loaded),
this finds a decrypted header in RAM and recovers the keystream:

    key = RAM_decrypted_header[0:1024] XOR disk_header[0:1024]

The pairing is **validated** before anything is written: a candidate key must decrypt
at least two other bundles to a `UnityFS` header whose declared size matches the file
on disk. That makes a wrong pairing (or a header that belongs to no bundle on disk)
report itself instead of producing a wrong key. Read-only: no hooks, no writes to the
game.

Usage
-----
    .venv/bin/python harvest_key.py                    # -> true_key_1024.bin
    .venv/bin/python harvest_key.py --gadget 127.0.0.1:27042
    .venv/bin/python harvest_key.py --dump-only        # keep the RAM header only
    .venv/bin/python harvest_key.py --out key.bin --header-out ram_header.bin

Run it while a song is loading or in song select. The scan looks for a `UnityFS`
header at either bundle version this install uses (7 and 8).
"""
import argparse
import os
import struct
import sys
import time

import ez2lib

# A decrypted header in RAM: signature + big-endian version. This install uses both
# bundle versions (7 and 8), so scan for either explicitly rather than relying on a
# wildcard.
SCAN_PATTERNS = [
    "55 6e 69 74 79 46 53 00 00 00 00 07",
    "55 6e 69 74 79 46 53 00 00 00 00 08",
]

FRIDA_JS = """
rpc.exports = {
    scanHeaders: function(patterns) {
        const ranges = Process.enumerateRanges("rw-");
        for (let i = 0; i < ranges.length; i++) {
            const r = ranges[i];
            if (r.size < 128 * 1024) continue;
            for (const pat of patterns) {
                try {
                    const hits = Memory.scanSync(r.base, Math.min(r.size, 0x2000000), pat);
                    for (const h of hits) {
                        return [h.address.toString(), h.address.readByteArray(1024)];
                    }
                } catch (e) {}
            }
        }
        return null;
    }
};
"""


def parse_header_size(pt: bytes):
    """The bundle size from a decrypted UnityFS header, or None if it is not one.

    UnityFS stores the size big-endian after two NUL-terminated version strings.
    """
    if not pt.startswith(b"UnityFS"):
        return None
    o = 8 + 4
    try:
        for _ in range(2):
            o = pt.index(0, o) + 1
        return struct.unpack_from(">q", pt, o)[0]
    except (ValueError, struct.error):
        return None


def disk_headers():
    """(path, first 1024 bytes, already_plaintext) for every bundle on disk."""
    out = []
    for pdir in ez2lib.PACKS_DIRS:
        if not os.path.isdir(pdir):
            continue
        for fn in sorted(os.listdir(pdir)):
            path = os.path.join(pdir, fn)
            with open(path, "rb") as f:
                head = f.read(1024)
            if len(head) < 1024:
                continue
            out.append((path, head, head.startswith(b"UnityFS")))
    return out


def derive_key(ram_header: bytes, bundles):
    """Recover the keystream by pairing `ram_header` with each encrypted disk header.

    A candidate is accepted only when it decrypts at least two *other* bundles to a
    UnityFS header whose size matches the file. Returns (key, path) or (None, None).
    """
    for path, head, plain in bundles:
        if plain:
            continue
        candidate = bytes(a ^ b for a, b in zip(ram_header, head))
        ok = 0
        for other_path, other_head, other_plain in bundles:
            if other_plain or other_path == path:
                continue
            dec = bytes(a ^ b for a, b in zip(other_head, candidate))
            if parse_header_size(dec) == os.path.getsize(other_path):
                ok += 1
                if ok >= 2:
                    return candidate, path
    return None, None


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gadget", default="127.0.0.1:27042",
                    help="Frida Gadget address (default: 127.0.0.1:27042)")
    ap.add_argument("--out", default=os.path.join(ez2lib.ROOT, ez2lib.BUNDLE_KEY_NAME),
                    help="where to write the derived key")
    ap.add_argument("--header-out", default="decrypted_header_ram.bin",
                    help="where to keep the RAM header if the key cannot be derived")
    ap.add_argument("--interval", type=float, default=2.0, help="poll interval in seconds")
    ap.add_argument("--timeout", type=float, default=120.0, help="give up after this many seconds")
    ap.add_argument("--dump-only", action="store_true",
                    help="save the RAM header and stop (do not derive the key)")
    args = ap.parse_args()

    try:
        import frida
    except ImportError:
        sys.exit("[!] 'frida' is not installed; run with .venv/bin/python harvest_key.py")

    print("[+] Connecting to Frida Gadget at %s..." % args.gadget)
    try:
        device = frida.get_device_manager().add_remote_device(args.gadget)
        session = device.attach("Gadget")
    except Exception as e:
        sys.exit("[!] Error connecting to Frida Gadget: %s" % e)

    script = session.create_script(FRIDA_JS)
    script.load()
    print("[+] Connected. Please select/start a song in the game.")
    print("[*] Polling memory for a loaded UnityFS header (read-only)...")

    ram_header = None
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        try:
            res = script.exports_sync.scan_headers(SCAN_PATTERNS)
        except Exception as e:
            res = None
            print("[!] Scan warning: %s" % e)
        if res:
            _addr, header_bytes = res
            ram_header = bytes(header_bytes)
            print("[+] Found a decrypted UnityFS header at RAM address %s" % _addr)
            break
        time.sleep(args.interval)

    if ram_header is None:
        session.detach()
        sys.exit("[!] No UnityFS header found in %.0fs. Make sure a song is loading "
                 "and the game is running." % args.timeout)

    if args.dump_only:
        with open(args.header_out, "wb") as f:
            f.write(ram_header)
        session.detach()
        print("[+] RAM header saved to %s" % args.header_out)
        return

    bundles = disk_headers()
    if not bundles:
        with open(args.header_out, "wb") as f:
            f.write(ram_header)
        session.detach()
        sys.exit("[!] No bundles on disk under %s; dumped the RAM header to %s instead."
                 % (ez2lib.PACKS_DIRS[0], args.header_out))

    key, source = derive_key(ram_header, bundles)
    session.detach()

    if key is None:
        with open(args.header_out, "wb") as f:
            f.write(ram_header)
        sys.exit("[!] Could not match the RAM header to any bundle on disk; saved it to "
                 "%s. Re-run while a song is loading." % args.header_out)

    if os.path.exists(args.out):
        with open(args.out, "rb") as f:
            if f.read() == key:
                print("[+] %s is already correct (derived key matches)." % args.out)
                return
        os.replace(args.out, args.out + ".bak")
        print("[*] Existing key backed up to %s.bak" % args.out)
    with open(args.out, "wb") as f:
        f.write(key)
    print("[+] Derived the %d-byte master key from %s" % (len(key), os.path.basename(source)))
    print("[+] Wrote %s" % args.out)


if __name__ == "__main__":
    main()
