import frida, json, time, sys
dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
s = dev.attach('Gadget')
sc = s.create_script(open('../build/_poll_da_run.js').read())
sc.load()
log = open('_poll_da.log', 'a', buffering=1)
last = None
t0 = time.time()
end = t0 + int(sys.argv[1] if len(sys.argv) > 1 else 900)
while time.time() < end:
    try:
        o = sc.exports_sync.snap()
    except Exception as e:
        log.write(json.dumps({"t": round(time.time()-t0,1), "err": str(e)}) + "\n"); time.sleep(0.5); continue
    key = o.get('co') + '|' + str(o.get('rjl')) + '|' + str(o.get('rjm')) + '|' + str(o.get('rjn'))
    if key != last:
        last = key
        log.write(json.dumps({"t": round(time.time()-t0,1), "state": o}) + "\n")
        if o.get('co') not in (None, '0x0') and o.get('rjm') != 'ERR':
            for w in ('rjl','rjm','rjn'):
                try:
                    h = sc.exports_sync.dumpfull(w)
                    open('extracted_charts/_live/da_rus_%s_%d.bin' % (w, int(time.time())), 'wb').write(bytes.fromhex(h))
                except Exception as e:
                    log.write(json.dumps({"dump": w, "err": str(e)}) + "\n")
    time.sleep(0.25)
log.write(json.dumps({"t": round(time.time()-t0,1), "end": True}) + "\n")
