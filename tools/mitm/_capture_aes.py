#!/usr/bin/env python3
"""Safe AesTransform/RijndaelManagedTransform .ctor hook driver.
Captures every distinct AES key/IV used, so we can identify the CDN key.

Usage: .venv/bin/python _capture_aes.py [seconds]
"""
import frida, time, sys, signal, os

DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 150
LOG = "_capture_aes.log"

dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
s = dev.attach("Gadget")
sc = s.create_script(open("../build/_hook_aes2_run.js").read())
sc.load()
r = sc.exports_sync.start()
print("hook result:", r, flush=True)

seen = {}
log = open(LOG, "a", buffering=1)
log.write(f"\n=== run {time.strftime('%H:%M:%S')} dur={DUR} ===\n")
t0 = time.time()
try:
    while time.time() - t0 < DUR:
        ev = sc.exports_sync.drain()
        for e in ev:
            arrs = e["arrs"]
            key = iv = None
            for a in arrs:
                if a["len"] in (16, 24, 32) and key is None:
                    key = a
                elif a["len"] == 16 and key is not None and iv is None:
                    iv = a
            sig = (key["hex"] if key else None, iv["hex"] if iv else None)
            if sig not in seen:
                seen[sig] = 0
                line = (f"[NEW] cls={e['cls']} key={sig[0]} iv={sig[1]} "
                        f"args={[(a['i'], a['len'], a['hex'][:48]) for a in arrs]}")
                print(line, flush=True)
                log.write(line + "\n")
            seen[sig] += 1
        time.sleep(0.4)
except KeyboardInterrupt:
    pass
print(f"done. distinct key/iv pairs: {len(seen)}", flush=True)
for k, c in seen.items():
    print(f"  key={k[0]} iv={k[1]} count={c}")
s.detach()
