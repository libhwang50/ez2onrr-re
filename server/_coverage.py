#!/usr/bin/env python3
"""Chart coverage audit for the private server.

    python server/_coverage.py            # summary + missing songs
    python server/_coverage.py --queue    # also write the capture queue
    python server/_coverage.py --log      # what the game has asked for so far
    python server/_coverage.py --json     # machine-readable

Coverage is counted **per song, not per variant**. The client never chooses the
CDN path — it downloads whatever URL the server hands it — so one captured
variant can be served for every keymode/difficulty of that song (see
`_exp.py chart any`). The `.ezi` is already byte-identical across a song's
variants, and `gamemode` is not a chart selector, so the two entries the music
list carries per song (GAME_MODE 1 and 2) collapse into one.

`--log` reads `server/pserver.log`: every `pattern:` line is one request the
game made, which is how a capture macro's progress (and its misses) can be
verified without looking at the screen.
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, 'server', 'data')
LOG = os.path.join(ROOT, 'server', 'pserver.log')
QUEUE = os.path.join(DATA, 'coverage_queue.json')

KEYMODE_DIR = {1: '4k', 2: '5k', 3: '6k', 4: '7k', 5: '8k'}
LEVEL_DIR = {1: 'ez', 2: 'nm', 3: 'hd', 4: 'shd'}


def norm(s):
    return re.sub(r'[^a-z0-9]', '', (s or '').lower())


def songs():
    """The music list, deduplicated by normalized title, in list order."""
    ml = json.load(open(os.path.join(DATA, 'gameinfo.json')))['musicList']
    by_norm = {}
    for m in ml:
        n = norm(m.get('TITLE'))
        if not n:
            continue
        e = by_norm.setdefault(n, {'title': m.get('TITLE'), 'norm': n,
                                   'id': m.get('MUSIC_ID'), 'modes': set()})
        e['modes'].add(m.get('GAME_MODE'))
    for e in by_norm.values():
        e['modes'] = sorted(e['modes'])
    return list(by_norm.values())


def charts():
    try:
        cs = json.load(open(os.path.join(DATA, 'charts.json')))
    except FileNotFoundError:
        return []
    return cs


def archive_variants():
    """Variant dirs present in extracted_charts/ (the raw capture archive)."""
    out = {}
    base = os.path.join(ROOT, 'extracted_charts')
    if not os.path.isdir(base):
        return out
    for song in sorted(os.listdir(base)):
        d = os.path.join(base, song)
        if not os.path.isdir(d):
            continue
        vs = set()
        for km in os.listdir(d):
            if not os.path.isdir(os.path.join(d, km)):
                continue
            for lm in os.listdir(os.path.join(d, km)):
                if os.path.isfile(os.path.join(d, km, lm, 'ez.ez')):
                    vs.add((km.lower(), lm.lower()))
        if vs:
            out[norm(song)] = vs
    return out


def parse_log():
    """(song, km, lm) requests seen in pserver.log, split by outcome."""
    ok, miss = {}, {}
    if not os.path.exists(LOG):
        return ok, miss
    pat = re.compile(r"pattern: '?([^']*?)'? km=(\d+) lm=(\d+) -> (.*)$")
    for line in open(LOG, errors='replace'):
        m = pat.search(line)
        if not m:
            continue
        name, km, lm, res = m.group(1), int(m.group(2)), int(m.group(3)), m.group(4)
        key = (norm(name), km, lm)
        if res.startswith('NO '):
            miss[key] = miss.get(key, 0) + 1
        else:
            ok[key] = res.strip()
    return ok, miss


def main():
    args = set(sys.argv[1:])
    lsongs = songs()
    cs = charts()
    by_song = {}
    for c in cs:
        by_song.setdefault(c['song_norm'], set()).add(
            (c['keymode'], c['levelmode']))
    arch = archive_variants()

    covered = [s for s in lsongs if s['norm'] in by_song]
    missing = [s for s in lsongs if s['norm'] not in by_song]
    # charts whose name matches no list entry (resource names can differ from
    # TITLE) — captured, but not attributable to a listed song
    listed = {s['norm'] for s in lsongs}
    orphan = sorted(k for k in by_song if k not in listed)

    if '--json' in args:
        print(json.dumps({
            'songs': len(lsongs), 'covered': len(covered),
            'missing': [s['title'] for s in missing],
            'orphan_charts': orphan,
            'variants': {k: sorted(f'{KEYMODE_DIR.get(a, a)}/{LEVEL_DIR.get(b, b)}'
                                   for a, b in v) for k, v in by_song.items()},
        }, indent=1, ensure_ascii=False))
        return 0

    pct = 100.0 * len(covered) / max(1, len(lsongs))
    print(f'charts: {len(cs)} captured variants over {len(by_song)} song names')
    print(f'songs : {len(covered)}/{len(lsongs)} covered ({pct:.1f}%)')
    print(f'raw archive: {len(arch)} song dirs with a decrypted ez.ez')

    if arch:
        only_arch = sorted(set(arch) - set(by_song))
        if only_arch:
            print(f'  NOTE: {len(only_arch)} song dirs in extracted_charts are not in '
                  f'charts.json ({", ".join(only_arch[:5])}…) — re-run _build_data.py')
    if orphan:
        print(f'  NOTE: {len(orphan)} chart names match no music-list title '
              f'({", ".join(orphan[:5])}…) — resource name != TITLE, still servable')

    print('\ncaptured variants per song:')
    for s in covered:
        vs = sorted(by_song[s['norm']])
        pretty = ' '.join(f'{KEYMODE_DIR.get(a, a)}/{LEVEL_DIR.get(b, b)}' for a, b in vs)
        print(f'  {s["title"][:28]:28s} {s["id"]:<6} {pretty}')
    if missing:
        print(f'\nmissing ({len(missing)} songs, in music-list order):')
        for s in missing[:40]:
            print(f'  {s["title"][:28]:28s} {s["id"]}')
        if len(missing) > 40:
            print(f'  … {len(missing) - 40} more')

    if '--queue' in args:
        json.dump([{'title': s['title'], 'id': s['id']} for s in missing],
                  open(QUEUE, 'w'), indent=1, ensure_ascii=False)
        print(f'\nwrote {QUEUE} — {len(missing)} songs, music-list order')

    if '--log' in args:
        ok, miss = parse_log()
        print(f'\nrequests seen in pserver.log: {len(ok)} served, {len(miss)} unanswered')
        # songs the game asked for but that we could not serve
        need = {}
        for (n, km, lm), cnt in miss.items():
            need.setdefault(n, []).append((km, lm, cnt))
        if need:
            print('  asked-for but unserved (the capture targets):')
            for n in sorted(need):
                vs = ' '.join(f'{KEYMODE_DIR.get(a, a)}/{LEVEL_DIR.get(b, b)}x{c}'
                              for a, b, c in sorted(need[n]))
                print(f'    {n:24s} {vs}')
        last = list(ok.items())[-8:]
        if last:
            print('  last served:')
            for (n, km, lm), res in last:
                print(f'    {n:24s} {KEYMODE_DIR.get(km, km)}/{LEVEL_DIR.get(lm, lm)} -> {res[:60]}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
