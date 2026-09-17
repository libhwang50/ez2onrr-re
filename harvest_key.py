#!/usr/bin/env python3
"""
EZ2ON REBOOT: R - Zero-Hook Decrypted Header Harvester
Scans RAM without modifying executable code (avoids Anti-Cheat crash).
"""

import frida
import sys
import time
import os

def main():
    print("[+] Connecting to Frida Gadget at 127.0.0.1:27042...")
    try:
        device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
        session = device.attach("Gadget")
    except Exception as e:
        print(f"[!] Error connecting to Frida Gadget: {e}")
        sys.exit(1)

    script_code = """
    rpc.exports = {
        scanHeaders: function() {
            const ranges = Process.enumerateRanges("rw-");
            for (let i = 0; i < ranges.length; i++) {
                const r = ranges[i];
                if (r.size < 128 * 1024) continue;
                try {
                    const results = Memory.scanSync(r.base, Math.min(r.size, 0x2000000), "55 6e 69 74 79 46 53 00 00 00 00 07");
                    for (let j = 0; j < results.length; j++) {
                        const match = results[j];
                        const head = match.address.readByteArray(1024);
                        return [match.address.toString(), head];
                    }
                } catch(e) {}
            }
            return null;
        }
    };
    """

    script = session.create_script(script_code)
    script.load()
    print("[+] Zero-Hook Harvester connected and active!")
    print("[+] Please select/start a song in the game.")
    print("[*] Polling heap memory for loaded UnityFS asset bundles...")

    captured = False
    for attempt in range(60):
        try:
            res = script.exports_sync.scan_headers()
            if res:
                addr, header_bytes = res
                header = bytes(header_bytes)
                print(f"\n[+] SUCCESS! Found decrypted UnityFS header at RAM address {addr} ({len(header)} bytes)!")

                with open("EZ2ON REBOOT R/decrypted_header_ram.bin", "wb") as f:
                    f.write(header)

                captured = True
                break
        except Exception as e:
            print(f"[!] Scan warning: {e}")
        time.sleep(2)

    if captured:
        print("[+] Decrypted header saved to EZ2ON REBOOT R/decrypted_header_ram.bin.")
    else:
        print("[!] No UnityFS header detected yet. Please ensure a song is selected/loaded.")

if __name__ == "__main__":
    main()
