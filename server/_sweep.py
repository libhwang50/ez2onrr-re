#!/usr/bin/env python3
"""Drive the game through the song list so the private server records charts.

The *server log is the sensor*: every `c2s_get_pattern_file` request names the
song, keymode, levelmode and gamemode, so the sweep never has to see the screen.
It presses keys, waits for a request it has not seen before, and moves on.

    python server/_sweep.py --watch            # just tail the log (no input)
    python server/_sweep.py --dry-run          # show bindings + plan, send nothing
    python server/_sweep.py --calibrate        # DEDUCE the keys from the request JSON
    python server/_sweep.py --limit 50         # capture 50 song entries
    python server/_sweep.py --variants         # also cycle difficulty/keymode
    python server/_sweep.py --shot             # save a screenshot before each entry

Capture run (one entry per song is enough — the server serves a song's chart for
any of its keymodes, and the .ezi is per-song):

    python server/_exp.py harvest            # hybrid + chart exact + minted token
    python server/_sweep.py --calibrate      # once, to learn the keys
    python server/_sweep.py --limit 600      # walk the list
    python server/_build_data.py && python server/_coverage.py

Safety: keys go to the FOCUSED window, so every input is preceded by a check that
the focused window really is the game (`niri msg focused-window`). Without the
compositor's answer, or in any other app, the sweep refuses to type.
"""
import json
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, 'server', 'data')
LOG = os.path.join(ROOT, 'server', 'pserver.log')
KEYS = os.path.join(DATA, 'sweep_keys.json')
PROGRESS = os.path.join(DATA, 'sweep_progress.jsonl')
SHOTS = os.path.join(ROOT, 'server', 'shots')
SHOTDIR = os.path.expanduser('~/Pictures/Screenshots')

DEFAULTS = {
    '_comment': ('Song-select key names for xdotool. Namazu wiki: 0-9 jump to a '
                 'list section, PageUp/Down move 8 rows, a-z jump by initial, '
                 'F6 random. Keypad 4/5/6/8 change the on-screen values '
                 '(difficulty/keymode) - verify with --calibrate.'),
    'game_app_id': 'steam_app_1477590',
    'keys': {
        'next_song': 'Down', 'prev_song': 'Up',
        'page_down': 'Next', 'page_up': 'Prior',
        'enter_song': 'Return', 'back': 'Escape',
        'diff_next': 'KP_8', 'diff_prev': 'KP_2',
        'keymode_next': 'KP_6', 'keymode_prev': 'KP_4',
    },
    'resync': ['Escape', 'Escape', 'Escape'],
    'timing': {'after_key': 0.35, 'settle': 1.0, 'wait_for_request': 25.0,
               'after_back': 1.5, 'poll': 0.25},
}

REQ = re.compile(r'c2s_get_pattern_file request: (\{.*\})')
SERVED = re.compile(r"pattern: '?(?P<name>[^']*?)'? km=(?P<km>\d+) lm=(?P<lm>\d+) -> (?P<how>.*)$")


def load_keys():
    if not os.path.exists(KEYS):
        os.makedirs(DATA, exist_ok=True)
        json.dump(DEFAULTS, open(KEYS, 'w'), indent=1, ensure_ascii=False)
        print(f'wrote {KEYS} with defaults')
    cfg = json.load(open(KEYS))
    merged = dict(DEFAULTS)
    merged.update({k: v for k, v in cfg.items() if not k.startswith('_')})
    merged['keys'] = {**DEFAULTS['keys'], **cfg.get('keys', {})}
    merged['timing'] = {**DEFAULTS['timing'], **cfg.get('timing', {})}
    return merged


CFG = load_keys()
K = CFG['keys']
T = CFG['timing']


# ---------------------------------------------------------------- input
def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=20)


def focused_app():
    r = run(['niri', 'msg', 'focused-window'])
    m = re.search(r'App ID: "([^"]*)"', r.stdout)
    return m.group(1) if m else None


def game_focused(verbose=False):
    app = focused_app()
    if app == CFG['game_app_id']:
        return True
    if verbose:
        print(f'  REFUSING to send keys: focused window is {app!r}, '
              f'expected {CFG["game_app_id"]!r} (focus the game first)')
    return False


def send(key_name, describe=None):
    """Press one configured binding (keys go to the focused window)."""
    if not game_focused(verbose=True):
        raise SystemExit(2)
    r = run(['xdotool', 'key', '--clearmodifiers', key_name])
    if r.returncode != 0:
        print(f'  xdotool failed for {key_name!r}: {r.stderr.strip()}')
        return False
    if describe:
        print(f'  {describe}: {key_name}')
    time.sleep(T['after_key'])
    return True


def screenshot(tag):
    os.makedirs(SHOTS, exist_ok=True)
    before = set(os.listdir(SHOTDIR)) if os.path.isdir(SHOTDIR) else set()
    run(['niri', 'msg', 'action', 'screenshot-screen'])
    time.sleep(1.0)
    try:
        new = sorted(set(os.listdir(SHOTDIR)) - before)
    except Exception:
        new = []
    if not new:
        return None
    src = os.path.join(SHOTDIR, new[-1])
    dst = os.path.join(SHOTS, f'{tag}_{int(time.time())}.png')
    os.replace(src, dst)
    print(f'  shot -> {os.path.relpath(dst, ROOT)}')
    return dst


# ---------------------------------------------------------------- log
class Tail:
    def __init__(self, path):
        self.path = path
        self.pos = 0
        self.seen = set()
        if os.path.exists(path):
            self.pos = os.path.getsize(path)
            for req in self.read_all():
                self.seen.add(self.key(req))

    def key(self, r):
        return (r.get('musicresourcename', '').lower(), r.get('keymode'),
                r.get('levelmode'), r.get('gamemode'))

    def read_all(self):
        out = []
        if not os.path.exists(self.path):
            return out
        with open(self.path, errors='replace') as f:
            for line in f:
                m = REQ.search(line)
                if m:
                    try:
                        out.append(json.loads(m.group(1)))
                    except Exception:
                        pass
        return out

    def poll(self):
        """New requests since the last call."""
        out = []
        if not os.path.exists(self.path):
            return out
        size = os.path.getsize(self.path)
        if size < self.pos:          # rotated/truncated
            self.pos = 0
        with open(self.path, errors='replace') as f:
            f.seek(self.pos)
            for line in f:
                m = REQ.search(line)
                if m:
                    try:
                        out.append(json.loads(m.group(1)))
                    except Exception:
                        pass
            self.pos = f.tell()
        return out

    def wait(self, timeout):
        end = time.time() + timeout
        while time.time() < end:
            for r in self.poll():
                return r
            time.sleep(T['poll'])
        return None


def progress(rec):
    with open(PROGRESS, 'a') as f:
        f.write(json.dumps(rec, ensure_ascii=False) + '\n')


# ---------------------------------------------------------------- modes
def watch():
    tail = Tail(LOG)
    print(f'watching {os.path.relpath(LOG, ROOT)} — Ctrl-C to stop '
          f'({len(tail.seen)} requests seen so far)')
    n = 0
    try:
        while True:
            for r in tail.poll():
                n += 1
                k = tail.key(r)
                print(f'  [{n:4d}] {k[0]:24s} km={k[1]} lm={k[2]} gm={k[3]}')
            time.sleep(0.4)
    except KeyboardInterrupt:
        print(f'\nstopped after {n} new requests')


def calibrate(limit=8):
    """Deduce which keys change difficulty vs keymode, straight from the request.

    Enters a song, reads keymode/levelmode out of the request the game makes,
    backs out, presses one candidate key, and enters again. Whatever changed is
    what that key does. Works because the request is self-describing.
    """
    tail = Tail(LOG)
    candidates = ['KP_1', 'KP_2', 'KP_3', 'KP_4', 'KP_5', 'KP_6', 'KP_7',
                  'KP_8', 'KP_9', 'Next', 'Prior']
    print('calibration: this presses keys in the game — keep it focused.\n'
          'First, verify enter/back with one entry:')
    base = enter_and_read(tail, 'baseline')
    if base is None:
        print('  could not read a request after pressing '
              f'{K["enter_song"]!r} — is a song selected, and is the sweep in '
              'harvest (hybrid) mode?')
        return 2
    print(f'  baseline: {base[0]} km={base[1]} lm={base[2]} gm={base[3]}')
    findings = {}
    for cand in candidates[:limit]:
        send(cand, f'pressing candidate')
        got = enter_and_read(tail, cand, quiet=True)
        if got is None:
            print(f'    {cand:6s} -> no request (ignored?)')
            continue
        what = []
        if got[1] != base[1]:
            what.append(f'keymode {base[1]}->{got[1]}')
        if got[2] != base[2]:
            what.append(f'levelmode {base[2]}->{got[2]}')
        findings[cand] = what
        print(f'    {cand:6s} -> {", ".join(what) if what else "nothing changed"}')
        if what:
            base = got          # follow the change so the next key is isolated
    print('\nwhat each candidate key does:')
    for cand, what in findings.items():
        if not what:
            continue
        print(f'  {cand:6s} -> {", ".join(what)}')
    print(f'  (nothing else changed anything — press them again in the game and\n'
          f'   check the on-screen effect if a binding is still unknown)')
    print(f'\nwrite the two that matter into {os.path.relpath(KEYS, ROOT)}:')
    print('  "diff_next" / "diff_prev"  (difficulty)')
    print('  "keymode_next" / "keymode_prev"  (key mode)')
    return 0


def enter_and_read(tail, tag, quiet=False):
    """Press enter (and later back), returning the request the game made."""
    tail.poll()                      # clear
    send(K['enter_song'], None if quiet else f'{tag}: enter')
    req = tail.wait(T['wait_for_request'])
    send(K['back'], None if quiet else f'{tag}: back')
    time.sleep(T['after_back'])
    if req is None:
        return None
    return (req.get('musicresourcename'), int(req.get('keymode') or 0),
            int(req.get('levelmode') or 0), req.get('gamemode'))


def resync():
    if not game_focused(verbose=True):
        return
    for key in CFG['resync']:
        run(['xdotool', 'key', '--clearmodifiers', key])
        time.sleep(0.5)
    print('  resync sent')


def sweep(limit, variants, shot, dry):
    tail = Tail(LOG)
    print(f'{"DRY RUN — " if dry else ""}sweep: up to {limit} entries, '
          f'{len(tail.seen)} requests already in the log')
    print(f'  bindings: enter={K["enter_song"]!r} back={K["back"]!r} '
          f'next={K["next_song"]!r}')
    if dry:
        print('  would: [shot] enter -> wait for a new request -> back -> '
              'next_song -> repeat')
        return 0
    if not game_focused(verbose=True):
        return 2
    captured = skipped = failed = 0
    try:
        for i in range(limit):
            if shot:
                screenshot(f'{i:04d}_before')
            send(K['enter_song'], f'[{i+1}/{limit}] enter')
            req = tail.wait(T['wait_for_request'])
            if req is None:
                failed += 1
                print('    no request — resyncing')
                resync()
                send(K['next_song'])
                continue
            k = tail.key(req)
            if k in tail.seen:
                skipped += 1
                print(f'    already known: {k[0]} km={k[1]} lm={k[2]} gm={k[3]}')
            else:
                captured += 1
                tail.seen.add(k)
                progress({'t': int(time.time()), 'song': k[0], 'keymode': k[1],
                          'levelmode': k[2], 'gamemode': k[3]})
                print(f'    CAPTURED  {k[0]:24s} km={k[1]} lm={k[2]} gm={k[3]}'
                      f'   ({captured} new)')
            send(K['back'], 'back')
            time.sleep(T['after_back'])
            if variants:
                for which, key in (('diff', K['diff_next']), ('diff', K['diff_next']),
                                   ('diff', K['diff_next']), ('mode', K['keymode_next'])):
                    send(key, f'  cycle {which}')
                    enter_and_read(tail, which, quiet=True)
            send(K['next_song'], 'next song')
            time.sleep(T['settle'])
    except KeyboardInterrupt:
        print('\ninterrupted')
    print(f'\ndone: {captured} captured, {skipped} already known, {failed} with no request')
    print(f'progress journal: {os.path.relpath(PROGRESS, ROOT)}')
    print('next: python server/_build_data.py && python server/_coverage.py')
    return 0


def main():
    a = sys.argv[1:]
    if '--watch' in a:
        return watch()
    if '--calibrate' in a:
        return calibrate()
    if '--dry-run' in a:
        return sweep(int(arg(a, '--limit', 10)), '--variants' in a, '--shot' in a, True)
    if not a:
        print(__doc__)
        print(f'sweep keys: {json.dumps(K, ensure_ascii=False)}')
        print(f'focused window right now: {focused_app()!r} '
              f'(game is {CFG["game_app_id"]!r})')
        return 0
    return sweep(int(arg(a, '--limit', 50)), '--variants' in a, '--shot' in a, False)


def arg(a, name, default):
    if name in a:
        return a[a.index(name) + 1]
    return default


if __name__ == '__main__':
    sys.exit(main())
