import frida, json
dm=frida.get_device_manager(); dev=dm.add_remote_device("127.0.0.1:27042")
s=dev.attach("Gadget"); sc=s.create_script(open("../build/_fields_run.js").read()); sc.load()
r=sc.exports_sync.run(); s.detach()
open("_fields_out.json","w").write(json.dumps(r,indent=1))
print("InGameCore fields:",len(r['ingame']),"crypt hits:",len(r['cryptHits']))
print("=== crypt hits ===")
for h in r['cryptHits']:
    print(f"  {h['ns']}.{h['cls']:32} {h['field']:26} off={h['off']:#06x} {h['type']}")
