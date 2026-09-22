#!/usr/bin/env python3
"""Send a probe to the running harvester (which owns the one safe Frida session).

    python server/_mem.py findhex <hex bytes>          # locate a value in memory
    python server/_mem.py readbytes <addr> [len]       # hex+ascii dump
    python server/_mem.py bck                          # current session bCK + scan for it
    python server/_mem.py hunt                         # error-site hunt stages (needs EZ2_HUNT=1)

The harvester must be running and attached; it polls server/cmd.json once a
second and answers in server/cmd_result.json.
"""
import base64
import json
import os
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CMD = os.path.join(ROOT, 'server', 'cmd.json')
RES = os.path.join(ROOT, 'server', 'cmd_result.json')
FULL = os.path.join(ROOT, 'server', 'data',
                    'last_upstream_c2s_get_pattern_file.full.json')


def send(cmd, timeout=180):
    if os.path.exists(CMD):
        raise SystemExit(f'{CMD} already exists — is the harvester stuck?')
    if os.path.exists(RES):
        os.remove(RES)
    json.dump(cmd, open(CMD, 'w'))
    global LAST_SAVED
    LAST_SAVED = None
    t0 = time.time()
    while time.time() - t0 < timeout:
        if os.path.exists(RES):
            d = json.load(open(RES))
            if d.get('cmd') == cmd:
                # keep a copy so a result is never lost to display quirks
                try:
                    json.dump(d, open(os.path.join(ROOT, 'server', 'last_probe.json'), 'w'),
                              indent=1, ensure_ascii=False)
                except Exception:
                    pass
                return d['result']
        time.sleep(0.5)
    raise SystemExit('timed out waiting for the harvester '
                     '(running? attached? server/cmd_result.json)')


def show(result, max_hits=20):
    d = json.loads(result) if isinstance(result, str) else result
    if 'err' in d:
        print('error:', d['err'])
        return
    # findlea / findthunk / findlit report their own shape
    if 'uniqueMethods' in d or 'offsets' in d or 'basesTried' in d:
        print(json.dumps({k: v for k, v in d.items() if k != 'sites'},
                         indent=1, ensure_ascii=False)[:3000])
        for s2 in (d.get('sites') or d.get('hits') or [])[:max_hits]:
            print('  ' + json.dumps(s2, ensure_ascii=False)[:300])
        return
    if 'hits' in d:
        print(f"pattern={d.get('pattern')} scanned={d.get('scannedMB')}MB "
              f"in {d.get('seconds')}s  hits={len(d['hits'])}")
        for h in d['hits'][:max_hits]:
            print(f"  {h['addr']}")
            print(f"    ascii: {h['ascii']}")
            print(f"    hex  : {h['hex']}")
        if len(d['hits']) > max_hits:
            print(f'  … {len(d["hits"]) - max_hits} more')
    elif 'ascii' in d:
        print(f"{d['addr']} ({d['len']}B)")
        print(f'  ascii: {d["ascii"]}')
        print(f'  hex  : {d["hex"]}')
    else:
        # unknown shape: print it in full (truncated) rather than mis-formatting
        print(json.dumps(d, indent=1, ensure_ascii=False)[:4000])


def main():
    import sys
    a = sys.argv[1:]
    if not a:
        print(__doc__)
        return 2
    if a[0] == 'findhex':
        if len(a) < 2:
            print('need a hex pattern (e.g. "44 f5 8d 9c")')
            return 2
        raw = a[1].replace(' ', '').replace('0x', '')
        pat = ' '.join(raw[i:i + 2] for i in range(0, len(raw), 2))
        show(send({'op': 'findhex', 'hex': pat,
                   'budgetMB': int(a[2]) if len(a) > 2 else 2048}))
    elif a[0] == 'readbytes':
        show(send({'op': 'readbytes', 'addr': a[1],
                   'len': int(a[2]) if len(a) > 2 else 64}))
    elif a[0] == 'bck':
        if not os.path.exists(FULL):
            print('no captured upstream pattern response yet — do a hybrid load first')
            return 1
        b = json.load(open(FULL))['bundleCryptKey']
        raw = base64.b64decode(b + '=' * (-len(b) % 4))
        print(f'session bCK (b64): {b}')
        print(f'             hex : {raw.hex()}')
        budget = int(a[1]) if len(a) > 1 else 16384
        print(f'scanning for the raw bytes (budget {budget} MB)…')
        show(send({'op': 'findhex',
                   'hex': ' '.join(f'{x:02x}' for x in raw),
                   'budgetMB': budget}))
        print('\nscanning for the base64 string form (UTF-8)…')
        show(send({'op': 'findhex', 'hex': ' '.join(
            f'{x:02x}' for x in b.encode())}))
        # the game's own strings are UTF-16, so a C# string field holding the
        # token would NOT match the UTF-8 scan above
        print('scanning for the base64 string form (UTF-16LE)…')
        show(send({'op': 'findhex', 'hex': ' '.join(
            f'{x:02x}' for x in b.encode('utf-16-le'))}))
    elif a[0] == 'findlitoff':
        # target address, static-fields base (the value `deref <global> 0xb8` prints)
        show(send({'op': 'findlitoff', 'target': a[1],
                   'sf': a[2] if len(a) > 2 else '0x71540000'}, timeout=600), max_hits=30)
    elif a[0] == 'findaccessor':
        show(send({'op': 'findaccessor', 'offset': a[1],
                   'len': a[2] if len(a) > 2 else ''}, timeout=900), max_hits=30)
    elif a[0] == 'deref':
        show(send({'op': 'deref', 'addr': a[1],
                   'offs': a[2] if len(a) > 2 else ''}, timeout=120))
    elif a[0] == 'findlea':
        show(send({'op': 'findlea', 'target': a[1]}, timeout=600), max_hits=60)
    elif a[0] == 'findlit':
        show(send({'op': 'findlit',
                   'len': int(a[1]),
                   'target': a[2] if len(a) > 2 else ''}, timeout=600), max_hits=45)
    elif a[0] == 'findthunk':
        # optional second arg: extra candidate bases (comma separated), e.g. the
        # base derived from findlit's impliedBase
        show(send({'op': 'findthunk', 'target': a[1],
                   'bases': a[2] if len(a) > 2 else ''}, timeout=900), max_hits=40)
    elif a[0] == 'hunt1':
        # the literal-data base + the neighbourhood of the anchored literal.
        # Default needle is the 8CN26 error-code text: the game's message table
        # holds "8CN26" immediately followed by "Song Load timeout".
        needle = a[1] if len(a) > 1 else 'CN26Song Load timeout'
        show(send({'op': 'hunt1', 'needle': needle}, timeout=600), max_hits=80)
    elif a[0] == 'hunt2':
        show(send({'op': 'hunt2', 'off': a[1]}, timeout=600))
    elif a[0] == 'hunt3':
        show(send({'op': 'hunt3', 'func': a[1]}, timeout=600))
    elif a[0] == 'hunt':
        print('use hunt1 / hunt2 <off> / hunt3 <funcVA> to drive the stages; '
              'EZ2_HUNT=1 still runs all three at attach')
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
