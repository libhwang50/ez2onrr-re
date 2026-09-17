#!/usr/bin/env python3
"""Generic driver runner: concat _il2cpp_bridge.js + <driver>.js, load into the
EZ2ON Frida Gadget, call rpc export, print JSON.

Usage:  python3 _r.py <driver.js> <export> [json_arg]
        python3 _r.py <driver.js> <export> --raw <arg>
"""
import frida, json, sys, os

BRIDGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '_il2cpp_bridge.js')


def main():
    driver = sys.argv[1]
    export = sys.argv[2]
    raw = False
    args = sys.argv[3:]
    if args and args[0] == '--raw':
        raw = True
        args = args[1:]
    src = open(BRIDGE).read() + '\n' + open(driver).read()
    dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
    s = dev.attach('Gadget')
    sc = s.create_script(src)
    sc.load()
    fn = getattr(sc.exports_sync, export)
    if not args:
        res = fn()
    else:
        parsed = []
        for a in args:
            try:
                parsed.append(json.loads(a))
            except Exception:
                parsed.append(a)
        res = fn(*parsed)
    if raw:
        sys.stdout.write(res if isinstance(res, str) else json.dumps(res))
    else:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    s.detach()


if __name__ == '__main__':
    main()
