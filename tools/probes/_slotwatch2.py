import frida, json, sys, time
dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
s = dev.attach('Gadget')
sc = s.create_script(open('../build/_slotwatch2_run.js').read())
out = open('_slotwatch2_log.jsonl', 'w', buffering=1)
def on_msg(m, d):
    if m.get('type') == 'send':
        out.write(json.dumps(m['payload']) + "\n")
    elif m.get('type') == 'error':
        out.write(json.dumps({"tag": "scriptError", "d": m.get('description')}) + "\n")
sc.on('message', on_msg)
sc.load()
out.write(json.dumps({"tag": "arm", "r": sc.exports_sync.arm()}) + "\n")
end = time.time() + int(sys.argv[1] if len(sys.argv) > 1 else 1200)
while time.time() < end:
    time.sleep(5)
    try:
        out.write(json.dumps({"tag": "state", "s": sc.exports_sync.state()}) + "\n")
    except Exception as e:
        out.write(json.dumps({"tag": "stateErr", "err": str(e)}) + "\n"); break
