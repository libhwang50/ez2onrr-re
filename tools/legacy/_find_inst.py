import frida, json
dm=frida.get_device_manager(); dev=dm.add_remote_device("127.0.0.1:27042")
s=dev.attach("Gadget"); sc=s.create_script(open("../build/_find_inst_run.js").read()); sc.load()
r=sc.exports_sync.run(); s.detach()
open("_inst_out.json","w").write(json.dumps(r,indent=1))
for cn,recs in r.items():
    print(f"=== {cn}: {len(recs)} instance(s) ===")
    for rec in recs:
        print("  @",rec['address'])
        for k,v in rec['vals'].items():
            if v is not None: print(f"      {k:22} = {v!r}")
