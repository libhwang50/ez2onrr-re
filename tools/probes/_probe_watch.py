import frida, json, sys, time
dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
s = dev.attach('Gadget')
sc = s.create_script(open('../build/_probe2_run.js').read())
sc.load()
log = open('_probe_log.jsonl', 'a', buffering=1)
last = None
end = time.time() + int(sys.argv[1] if len(sys.argv) > 1 else 900)
while time.time() < end:
    try:
        st = sc.exports_sync.state()
        mk = sc.exports_sync.find()
    except Exception as e:
        log.write(json.dumps({"t": time.time(), "err": str(e)}) + "\n"); time.sleep(2); continue
    key = json.dumps(st) + '|' + str(len(mk))
    if key != last:
        last = key
        log.write(json.dumps({"t": round(time.time(), 1), "state": st, "marker_count": len(mk), "marker_first": mk[:3]}) + "\n")
    time.sleep(1.0)
log.write(json.dumps({"t": round(time.time(),1), "end": True}) + "\n")
