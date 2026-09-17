import frida, time, signal, os, json
_LIVE=[None]
def cleanup():
    if _LIVE[0]:
        try: _LIVE[0].detach()
        except Exception: pass
def sig(s,f):
    cleanup(); os._exit(0)
signal.signal(signal.SIGTERM, sig)
dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
s = dev.attach("Gadget"); _LIVE[0]=s
sc = s.create_script(open("../build/_hook_aes_run.js").read())
seen = {}
def on_msg(m, data):
    if isinstance(m, dict) and m.get("type") == "send":
        p = m.get("payload")
        if isinstance(p, dict) and p.get("type") == "aes-ctor":
            key = iv = None
            for a in p["args"]:
                if a and a["len"] in (16, 24, 32) and key is None: key = a
                elif a and a["len"] == 16 and key is not None and iv is None: iv = a
            sig = (key["hex"] if key else None, iv["hex"] if iv else None)
            if sig not in seen:
                seen[sig] = 0
                print(f"[AES ctor] {p['label']} key={sig[0]} iv={sig[1]}  args={[(a['len'], a['hex'][:32]) for a in p['args'] if a]}", flush=True)
            seen[sig] += 1
        elif isinstance(p, str):
            print("  <agent>", p, flush=True)
sc.on("message", on_msg)
sc.load()
r = sc.exports_sync.start()
print("hooks:", r, flush=True)
print("listening for AES constructor calls (15s)...", flush=True)
time.sleep(15)
print("distinct key/iv pairs seen:", len(seen), flush=True)
for (k,iv),c in seen.items():
    print(f"  key={k} iv={iv} count={c}", flush=True)
cleanup()
