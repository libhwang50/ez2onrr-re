#!/usr/bin/env python3
"""ripper/check_charts.py — audit extracted_charts/ for captures that are filed wrong or incomplete.

Why this exists
---------------
`tools/live/dump_song.py` used to name the output directory from the *runtime* label and write the
fetched chart into it eagerly.  The game updates `ez_url`/`ezi_url` in stages, so a snapshot
taken mid-transition paired one variant's label with another variant's chart — which is how
Ultimatum's real 5-shd chart was overwritten by a 4K one.  The dumper now decrypts in memory
first and diverts a disagreement to `<name>_mismatch/`, but captures from before that can
still be filed wrong, and a crash mid-capture leaves artifacts missing.

Checks, per capture directory
-----------------------------
* **identity** — the chart's own key mode (playable-lane span, tracks 3-10) against the
  `<keymode>/` it is filed under, and the difficulty against the runtime request label
  when one is recorded.  Key mode comes from the lane span, not the header name: the
  header disagrees with the runtime request ~47% of the time (every 8K capture is tagged
  `6-*`).  The difficulty half of the header is a *base-variant* tag (an HD capture is
  often tagged `-nm`), so it is only a fallback when `ident.json` has no runtime label.
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
        ckm = ch.keymode
        cdiff = ch.difficulty
        info.update(name=name, ckm=ckm, diff=cdiff, lanes=ch.lane_count)
        if ckm and ckm != dir_km:
            problems.append('filed as %s but the chart is %s (%d lanes)'
                            % (dir_km, ckm, ch.lane_count))

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
            # Difficulty lives in the chart header too, but the header names the *base*
            # variant the chart was authored from (an HD capture is often tagged `-nm`,
            # a 6K one `5-`), so it is not the requested difficulty. Trust the runtime
            # request label when there is one; only fall back to the header otherwise.
            runtime_diff = (label.get('difficulty')
                            if label.get('labelSource') in ('runtime', 'pattern request')
                            else None)
            if runtime_diff:
                if runtime_diff.upper() != dir_diff:
                    problems.append('filed as %s but the request was %s'
                                    % (dir_diff, runtime_diff))
            elif cdiff and cdiff != dir_diff:
                problems.append('filed as %s but the chart name says %s '
                                '(no runtime difficulty recorded)' % (dir_diff, cdiff))
            info['label'] = '%s %s' % (lkm or '?', label.get('difficulty') or '?')

    return problems, info


def url_collisions(root):
    """Captured CDN URLs shared by two captures that hold *different* bodies.

    A stale/misassociated URL means the dumper's ident snapshot lagged the body
    it wrote (the URL/label race).  The private server maps each capture's URL
    path to its local body, so two captures on one path would serve one chart
    for two different requests.  ``server/_build_data.py`` mints a unique path
    when it hits a collision; this check flags the underlying captures.
    """
    import hashlib
    import urllib.parse
    seen = {}
    for ip in glob.glob(os.path.join(root, '*', '*', '*', 'ident.json')):
        d = os.path.dirname(ip)
        try:
            ident = json.load(open(ip)) or {}
        except Exception:
            continue
        for field, pref in (('ez_url', 'cdn_ez_'), ('ezi_url', 'cdn_ezi_')):
            p = urllib.parse.urlsplit(ident.get(field) or '').path
            if not p:
                continue
            f = [x for x in os.listdir(d) if x.startswith(pref)]
            if not f:
                continue
            fp = os.path.join(d, f[0])
            digest = hashlib.md5(open(fp, 'rb').read()).hexdigest()
            if p in seen and seen[p][1] != digest:
                yield p, os.path.relpath(seen[p][0], root), os.path.relpath(fp, root)
            seen[p] = (fp, digest)


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

    collisions = list(url_collisions(a.root))
    for p, first, second in collisions:
        print('!! stale URL: %s captured under both %s and %s'
              % (p, first, second))
    if collisions:
        bad += len(collisions)
        print('    (the second capture recorded a URL from a different capture;'
              ' re-capture it with the relay capture, or let _build_data.py '
              're-key it)')

    print('\n%d capture(s), %d with problems' % (len(dirs), bad))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
