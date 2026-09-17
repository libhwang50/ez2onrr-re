#!/usr/bin/env python3
"""check_charts.py — audit extracted_charts/ for captures that are filed wrong or incomplete.

Why this exists
---------------
`dump_song.py` used to name the output directory from the *runtime* label and write the
fetched chart into it eagerly.  The game updates `ez_url`/`ezi_url` in stages, so a snapshot
taken mid-transition paired one variant's label with another variant's chart — which is how
Ultimatum's real 5-shd chart was overwritten by a 4K one.  The dumper now decrypts in memory
first and diverts a disagreement to `<name>_mismatch/`, but captures from before that can
still be filed wrong, and a crash mid-capture leaves artifacts missing.

Checks, per capture directory
-----------------------------
* **identity** — the chart's own key mode (header name, else lane count) and difficulty
  against the `<keymode>/<difficulty>` it is filed under.  A chart that does not carry a
  difficulty in its name (`#PTMAKE`, `1_part1`, empty) is only checked on key mode.
* **artifacts** — which of the expected files are present.
* **record** — `ident.json`'s label agrees with the chart on disk.

Read-only.  Exits non-zero if any capture is wrong, so it can gate a batch.
"""
import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse_chart import parse_ez, load  # noqa: E402

LANE_KM = {4: '4K', 5: '5K', 6: '6K', 7: '7K', 8: '8K'}
EXPECTED = ('ez.ez', 'ezi.ezi', 'ident.json')


def check(d, root):
    """Return (problems, info) for one capture directory."""
    rel = os.path.relpath(d, root)
    parts = rel.split(os.sep)
    problems, info = [], {'rel': rel}

    if len(parts) != 3:
        problems.append('unexpected nesting (want <song>/<keymode>/<difficulty>)')
        return problems, info

    _song, dir_km, dir_diff = parts
    dir_km, dir_diff = dir_km.upper(), dir_diff.upper()

    for f in EXPECTED:
        if not os.path.exists(os.path.join(d, f)):
            problems.append('missing %s' % f)

    ez = os.path.join(d, 'ez.ez')
    if os.path.exists(ez):
        try:
            ch = parse_ez(load(ez)[0])
        except Exception as e:
            problems.append('ez.ez unreadable: %s' % e)
            return problems, info
        name = ch.header['name']
        ckm = ch.keymode or LANE_KM.get(ch.lane_count)
        cdiff = ch.difficulty
        info.update(name=name, ckm=ckm, diff=cdiff, lanes=ch.lane_count)
        if ckm and ckm != dir_km:
            problems.append('filed as %s but the chart is %s (%d lanes)'
                            % (dir_km, ckm, ch.lane_count))
        if cdiff and cdiff != dir_diff:
            problems.append('filed as %s but the chart name says %s' % (dir_diff, cdiff))

        ip = os.path.join(d, 'ident.json')
        if os.path.exists(ip):
            try:
                label = (json.load(open(ip)) or {}).get('label') or {}
            except Exception:
                label = {}
            lkm = label.get('keymode')
            if lkm and ckm and lkm != ckm:
                problems.append('ident.json label says %s but the chart is %s' % (lkm, ckm))
            if label.get('labelMismatch'):
                problems.append('ident.json records a label mismatch')
            info['label'] = '%s %s' % (lkm or '?', label.get('difficulty') or '?')

    return problems, info


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('root', nargs='?', default='extracted_charts',
                    help='capture root (default extracted_charts)')
    ap.add_argument('-q', '--quiet', action='store_true',
                    help='only report captures with problems')
    a = ap.parse_args()

    dirs = sorted({os.path.dirname(p) for p in glob.glob(os.path.join(a.root, '*', '*', '*',
                                                                     'ez.ez'))})
    if not dirs:
        sys.exit('no captures under %s' % a.root)

    bad = 0
    for d in dirs:
        problems, info = check(d, a.root)
        if problems:
            bad += 1
        if problems or not a.quiet:
            print('%-32s %-9s %-6s %-5s %s'
                  % (info['rel'], repr(info.get('name', '?')), info.get('ckm') or '?',
                     info.get('diff') or '?', 'OK' if not problems else ''))
            for p in problems:
                print('    !! %s' % p)

    print('\n%d capture(s), %d with problems' % (len(dirs), bad))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
