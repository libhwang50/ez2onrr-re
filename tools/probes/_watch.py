import frida, json, sys, time, threading
dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
s = dev.attach('Gadget')
src = open('_il2cpp_bridge.js').read() + "\n" + open('../build/_watch_run.js').read()
sc = s.create_script(src)
out = open('_watch_log.jsonl', 'a', buffering=1)
def on_msg(m, data):
    if m.get('type') == 'send':
        out.write(json.dumps(m['payload']) + "\n")
sc.on('message', on_msg)
sc.load()
out.write(json.dumps({"tag": "start", "pid": dev.get_process_by_name if False else None}) + "\n")
print('armed:', json.dumps(sc.exports_sync.arm())[:400])
end = time.time() + int(sys.argv[1] if len(sys.argv) > 1 else 1200)
n = 0
while time.time() < end:
    try:
        sc.exports_sync.poll()
        n += 1
    except Exception as e:
        out.write(json.dumps({"tag": "pollErr", "err": str(e)}) + "\n")
    time.sleep(0.01)
out.write(json.dumps({"tag": "end", "polls": n}) + "\n")
