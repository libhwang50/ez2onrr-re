import frida, json, sys, time

dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
s = dev.attach("Gadget")
sc = s.create_script(open("../build/_diag_run.js").read())
sc.load()

r = sc.exports_sync.run()
open("_diag_out.json", "w").write(json.dumps(r, indent=1))

print("=== InGameCore @", r.get("instance"), "===")
print("--- instance strings ---")
for k, v in r.get("strings", {}).items():
    vv = v if len(v) < 200 else v[:200] + "..."
    print(f"  {k:22} = {vv!r}")
print("--- instance bytearrays (first 96 hex chars) ---")
for k, v in r.get("bytearrays", {}).items():
    print(f"  {k:22} len={v['len']} {v['hex'][:96]}")
print("--- STATIC fields ---")
for k, v in r.get("statics", {}).items():
    if "str" in v:
        print(f"  {k:22} str = {v['str'][:120]!r}")
    elif "hex" in v:
        print(f"  {k:22} len={v['len']} {v['hex'][:96]}")
    else:
        print(f"  {k:22} {v}")
print("--- bools (true) ---")
for k, v in r.get("bools", {}).items():
    if v:
        print(f"  {k:22} = {v}")

print("\n=== EZFF heap scan ===")
t0 = time.time()
m = sc.exports_sync.scan_ezff()
print(f"scan took {time.time()-t0:.1f}s, {len(m)} hits")
for x in m:
    print(f"  {x['address']}  {x['ctx'][:64]}")

s.detach()
