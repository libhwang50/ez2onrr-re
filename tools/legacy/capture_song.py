#!/usr/bin/env python3
"""Capture a live EZ2ON chart from the running game's memory.

Prereqs: game running with Frida Gadget :27042 and a song loaded/paused.

Writes to extracted_charts/<tag>/:
  state.json        - InGameCore urls/key/pattern metadata
  chart.json        - parsed note/bpm/measure structures
  instrumentDic.json- keysound index (id -> filename)
  da_rus_*.bin      - raw downloaded ciphertext + per-song key (if present)
  meta.json         - combined summary
"""
import json, os, subprocess, sys, time

ROOT = os.path.dirname(os.path.abspath(__file__))
PY = os.path.join(ROOT, '.venv', 'bin', 'python')
RUN = os.path.join(ROOT, '_r.py')

FIELDS = [
    ('normalNoteData', 'em', True),
    ('longNoteData', 'eo', True),
    ('bpmNoteData', 'er', False),
    ('MeasureScaleData', 'et', False),
    ('VolumeData', 'es', False),
    ('BeatData', 'es', False),
    ('MeasureLineData', 'es', False),
    ('StopGimmickData', 'es', False),
]


def call(driver, export, *args):
    cmd = [PY, RUN, os.path.join(ROOT, driver), export] + [json.dumps(a) for a in args]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if p.returncode != 0:
        return {'__error__': p.stderr.strip()[-2000:]}
    try:
        return json.loads(p.stdout)
    except Exception:
        return {'__raw__': p.stdout}


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else time.strftime('song_%Y%m%d_%H%M%S')
    out = os.path.join(ROOT, 'extracted_charts', tag)
    os.makedirs(out, exist_ok=True)

    print('[*] state ...')
    state = call('../build/_state2_run.js', 's')
    json.dump(state, open(os.path.join(out, 'state.json'), 'w'), indent=2, ensure_ascii=False)
    cnts = {k: state.get(k) for k in ('instrumentDic', 'normalNoteData', 'longNoteData',
                                      'bpmNoteData', 'MeasureScaleData') if k in state}
    print('    counts:', json.dumps(cnts), 'url=', (state.get('ez_url') or '')[:60])

    print('[*] parsed chart ...')
    chart = {}
    for fn, ec, nested in FIELDS:
        r = call('../build/_dump_chart_run.js', 'dumpField', fn, ec, nested)
        chart[fn] = r
        print('    ', fn, '->', 'ERR' if '__error__' in r else (len(r.get('data', [])) if isinstance(r, dict) else '?'))
    json.dump(chart, open(os.path.join(out, 'chart.json'), 'w'), ensure_ascii=False)

    print('[*] instrumentDic ...')
    d = call('../build/_read_dict_run.js', 'run', 'instrumentDic', 100000)
    json.dump(d, open(os.path.join(out, 'instrumentDic.json'), 'w'), ensure_ascii=False)
    print('    count:', d.get('count'))

    print('[*] da.rus ciphertext/key ...')
    snap = call('../build/_poll_da_run.js', 'snap')
    if snap and snap.get('co') not in (None, '0x0'):
        meta = {'da_rus': snap}
        for w in ('rjl', 'rjm', 'rjn'):
            try:
                h = call('../build/_poll_da_run.js', 'dumpfull', w)
                if isinstance(h, str):
                    open(os.path.join(out, 'da_rus_%s.bin' % w), 'wb').write(bytes.fromhex(h))
                    meta[w + 'Len'] = len(bytes.fromhex(h))
            except Exception as e:
                meta[w + 'Err'] = str(e)
        json.dump(meta, open(os.path.join(out, 'da_rus.json'), 'w'), indent=2)
        print('    rjl/rjm/rjn captured')
    else:
        print('    da.rus not populated (song may not be in the right state)')

    # combined summary
    summary = {
        'tag': tag,
        'state': state,
        'chartCounts': {k: (len(v.get('data', [])) if isinstance(v, dict) and 'data' in v else None)
                        for k, v in chart.items()},
        'instrumentCount': d.get('count') if isinstance(d, dict) else None,
    }
    json.dump(summary, open(os.path.join(out, 'meta.json'), 'w'), indent=2, ensure_ascii=False)
    print('[+] done ->', out)


if __name__ == '__main__':
    main()
