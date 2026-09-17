import frida, json, sys
dm=frida.get_device_manager(); dev=dm.add_remote_device("127.0.0.1:27042")
s=dev.attach("Gadget")
sc=s.create_script(open("../build/_cap_now_run.js").read())
sc.load()
r=sc.exports_sync.run()
s.detach()
open("_cap_now_out.json","w").write(json.dumps(r,indent=1))
print(json.dumps(r,indent=1)[:6000])
