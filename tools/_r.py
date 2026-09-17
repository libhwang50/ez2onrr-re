#!/usr/bin/env python3
"""Run a generated driver from tools/build/ against the EZ2ON Frida Gadget.

Usage:  python3 tools/_r.py <driver> <export> [json_arg ...]

<driver> is the source basename (e.g. _vt) or a path; it is resolved to
tools/build/<name>_run.js, which build_run.sh generates as bridge+driver.
Add --raw to print the raw string result; add --save FILE to dump JSON.
"""
import frida, json, sys, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(ROOT, 'tools', 'build')


def resolve(driver):
    b = os.path.basename(driver)
    if b.endswith('.js'):
        b = b[:-3]
    if b.endswith('_run'):
        b = b[:-4]
    p = os.path.join(BUILD, b + '_run.js')
    if not os.path.exists(p):
        raise SystemExit('no generated driver: %s (run bash tools/il2cpp/build_run.sh)' % p)
    return p


def main():
    argv = sys.argv[1:]
    raw = '--raw' in argv
    save = None
    if '--save' in argv:
        i = argv.index('--save')
        save = argv[i + 1]
        del argv[i:i + 2]
    argv = [a for a in argv if a != '--raw']

    driver, export, args = argv[0], argv[1], argv[2:]
    src = open(resolve(driver)).read()
    dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
    s = dev.attach('Gadget')
    sc = s.create_script(src)
    sc.load()
    fn = getattr(sc.exports_sync, export)
    parsed = []
    for a in args:
        try:
            parsed.append(json.loads(a))
        except Exception:
            parsed.append(a)
    res = fn(*parsed)
    if save:
        with open(save, 'w') as f:
            json.dump(res, f, indent=2)
        print('wrote', save)
    if raw:
        sys.stdout.write(res if isinstance(res, str) else json.dumps(res))
    else:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    s.detach()


if __name__ == '__main__':
    main()
