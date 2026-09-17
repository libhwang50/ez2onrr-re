import frida, json
dm=frida.get_device_manager(); dev=dm.add_remote_device("127.0.0.1:27042")
s=dev.attach("Gadget"); sc=s.create_script(open("../build/_static_run.js").read()); sc.load()
r=sc.exports_sync.run(); s.detach()
open("_static_out.json","w").write(json.dumps(r,indent=1))
print("=== STATIC STRING VALUES ===")
for f in r:
    if f['static'] and f['type']=='System.String' and f['val'] is not None:
        print(f"  {f['cls']:6} {f['field']:28} = {f['val']!r}")
