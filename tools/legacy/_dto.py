import frida, json
dm=frida.get_device_manager(); dev=dm.add_remote_device("127.0.0.1:27042")
s=dev.attach("Gadget"); sc=s.create_script(open("../build/_dto_run.js").read()); sc.load()
r=sc.exports_sync.run(); s.detach()
open("_dto_out.json","w").write(json.dumps(r,indent=1))
for cls,flds in r.items():
    print(f"=== class {cls} ({len(flds)} fields) ===")
    for f in flds:
        st=" [STATIC]" if f['static'] else ""
        print(f"   {f['name']:28} off={f['off']:#06x} {f['type']}{st}")
