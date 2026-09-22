#!/usr/bin/env python3
"""Drive the game through the song list so the private server records charts.

The *server log is the sensor*: every `c2s_get_pattern_file` request names the
song, keymode, levelmode and gamemode, so the sweep never has to see the screen.
It presses keys, waits for a request it has not seen before, and moves on.

    python server/_sweep.py --watch            # just tail the log (no input)
    python server/_sweep.py --dry-run          # show bindings + plan, send nothing
    python server/_sweep.py --calibrate --write # DEDUCE the keys from the request JSON
    python server/_sweep.py --limit 50         # capture 50 song entries
    python server/_sweep.py --mode STANDARD [--from BASIC]   # step to that card first
    python server/_sweep.py --variants         # also cycle difficulty/keymode
    python server/_sweep.py --shot             # save a screenshot before each entry
    python server/_sweep.py --state            # classify the current screen and exit

The server log is the primary sensor (a request names song/keymode/levelmode/
gamemode, and CDN OK/HIT says whether it was captured). A screenshot classifier
(`server/_screen.py`) is the *safety* sensor: on a missed request it tells whether
the game is still in the previous song (pause menu safe), back at song select, or
at the main menu — instead of guessing whether ESC is safe.

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
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # for _screen
DATA = os.path.join(ROOT, 'server', 'data')
LOG = os.path.join(ROOT, 'server', 'pserver.log')
KEYS = os.path.join(DATA, 'sweep_keys.json')
PROGRESS = os.path.join(DATA, 'sweep_progress.jsonl')
SHOTS = os.path.join(ROOT, 'server', 'shots')

DEFAULTS = {
    '_comment': ('Song-select key names for xdotool: TAB = key mode (4B/5B/6B/8B) '
                 'change, UP/DOWN = song, LEFT/RIGHT = difficulty, ENTER = decide '
                 'and start. Careful: the game\'s hint bar labels those two arrow '
                 'pairs with icons that read the other way round - this mapping was '
                 'confirmed in game. --calibrate (--write) derives it empirically '
                 'from the request JSON if a build ever differs.'),
    'game_app_id': 'steam_app_1477590',
    'keys': {
        # song select. The card row WRAPS (Left from BASIC goes to OPTION), so
        # never spam a direction to reach a card - use --mode, which steps and
        # then verifies from the next request's gamemode.
        'next_song': 'Down', 'prev_song': 'Up',
        'next_diff': 'Right', 'prev_diff': 'Left',
        'keymode_next': 'Tab', 'keymode_prev': 'Tab',
        'enter_song': 'Return',          # ENTER 결정 (also starts a song)
        # list paging / jumps (NamuWiki): 0-9 sections, PageUp/Down 8 rows, a-z initial
        'page_down': 'Next', 'page_up': 'Prior',
    },
    # Leaving a song: ESC opens the pause menu with RESUME focused; Up uses the
    # focus wrap to land on the bottom button, MUSIC SELECT; ENTER confirms.
    'exit_song': ['Escape', 'Up', 'Return'],
    'resync': ['Escape', 'Up', 'Return'],
    # main menu: a WRAPPING card ring; 'cards' is its order (adjacent for the two
    # play modes), and --mode steps the short way round from --from.
    'menu': {'cards': ['BASIC', 'STANDARD', 'MULTIPLAYER', 'COURSE', 'LOUNGE', 'OPTION'],
             'confirm': 'Return'},
    'timing': {'after_key': 0.35, 'settle': 1.0, 'wait_for_request': 8.0,
               'after_exit': 2.5, 'after_start': 8.0, 'wait_for_cdn': 10.0,
               'after_failed_load': 3.0,
               'poll': 0.25,
               'after_confirm': 3.0},
}

REQ = re.compile(r'c2s_get_pattern_file request: (\{.*\})')
CDN = re.compile(r'CDN (OK|HIT|FAIL|MISS)\b(.*)$')
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
    """Save a frame of the game window. Focus-independent (XWayland + x11grab), so
    it works while the sweep's terminal holds the focus."""
    os.makedirs(SHOTS, exist_ok=True)
    try:
        import _screen
        from PIL import Image
        rgb = _screen.grab()
    except Exception as e:
        print(f'  shot failed: {e}')
        return None
    dst = os.path.join(SHOTS, f'{tag}_{int(time.time())}.png')
    Image.fromarray(rgb).save(dst)
    print(f'  shot -> {os.path.relpath(dst, ROOT)}')
    return dst


SCREEN = os.environ.get('EZ2_NO_SCREEN') not in ('1', 'true')


def screen_state():
    """(state, confidence, why) for the game window, or None if unavailable."""
    if not SCREEN:
        return None
    try:
        import _screen
        return _screen.classify(_screen.grab())
    except Exception as e:
        print(f'    (screen classifier unavailable: {e})')
        return None


def recover(still_in_song, shot_tag=None):
    """Get back to the song select after a missed request, using the screen state
    when it is available and the safe blind fallback otherwise.

    ESC is only safe once we know the game is in the previous song's pause menu:
    in the main menu ESC is 'leave', and an unprovoked Escape can walk the game out
    of song select. So: classify first, then act.
    """
    st = screen_state()
    state = st[0] if st else None
    if st:
        print(f'    screen state: {state} (conf={st[1]:.2f}, {st[2]})')
        if shot_tag:
            screenshot(shot_tag)
    if state in ('GAMEPLAY', 'PAUSE', 'RESULT') or (state is None and still_in_song):
        print('    still in the previous song — the pause menu is safe to use')
        resync()
    elif state == 'MAIN_MENU':
        print('    back at the main menu — re-entering the focused card')
        send(CFG['menu']['confirm'])
        time.sleep(T['after_confirm'])
    else:
        # SONG_SELECT or unknown: no ESC. Up+Enter is harmless everywhere and
        # re-enters a focused card / starts a song.
        print('    safe recovery (Up, Enter; no ESC)')
        send(K['prev_song'])
        send(K['enter_song'])


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


class CdnWatch:
    """Watches the log for CDN outcomes: a pattern request alone is not a
    capture — the chart has to come back from the CDN (OK/HIT) or the song
    still cannot be served, and must stay on the to-do list."""

    def __init__(self, path=LOG):
        self.path = path
        self.pos = 0
        self.n_ok = self.n_bad = 0
        for what, _rest in self.read_new():
            self._count(what)

    def _count(self, what):
        if what in ('OK', 'HIT'):
            self.n_ok += 1
        else:
            self.n_bad += 1

    def read_new(self):
        out = []
        if not os.path.exists(self.path):
            return out
        size = os.path.getsize(self.path)
        if size < self.pos:
            self.pos = 0
        with open(self.path, errors='replace') as f:
            f.seek(self.pos)
            for line in f:
                m = CDN.search(line)
                if m:
                    out.append((m.group(1), m.group(2).strip()))
            self.pos = f.tell()
        return out

    def baseline(self):
        self.read_new()
        return (self.n_ok, self.n_bad)

    def wait_new(self, timeout):
        """Wait for new CDN lines; returns [(what, rest), ...]."""
        end = time.time() + timeout
        got = []
        while time.time() < end:
            new = self.read_new()
            for what, rest in new:
                self._count(what)
                got.append((what, rest))
            if any(w in ('OK', 'HIT') for w, _ in got):
                return got
            time.sleep(T['poll'])
        return got


def progress(rec):
    with open(PROGRESS, 'a') as f:
        f.write(json.dumps(rec, ensure_ascii=False) + '\n')


# ---------------------------------------------------------------- modes
def watch():
    tail = Tail(LOG)
    print(f'watching {os.path.relpath(LOG, ROOT)} — Ctrl-C to stop '
          f'({len(tail.seen)} requests seen so far)')
    cdn = CdnWatch()
    n = 0
    try:
        while True:
            for r in tail.poll():
                n += 1
                k = tail.key(r)
                print(f'  [{n:4d}] request {k[0]:22s} km={k[1]} lm={k[2]} gm={k[3]}')
            for what, rest in cdn.read_new():
                print(f'         CDN {what} {rest[:90]}')
            time.sleep(0.4)
    except KeyboardInterrupt:
        print(f'\nstopped after {n} new requests')


def calibrate(write=False):
    """Deduce the song-select bindings straight from the request JSON.

    Enters a song (SHIFT), reads song/keymode/levelmode out of the request the
    game makes, backs out, presses one candidate key, and enters again. Whatever
    changed is what that key does — the request is self-describing, so this needs
    no screenshot and no guessing. `--write` stores the result in sweep_keys.json.
    """
    tail = Tail(LOG)
    # per the hint bar the arrows do one thing and TAB the keymode; the NamuWiki
    # keypad claim is tested too, in case this build maps them differently
    candidates = ['Left', 'Right', 'Up', 'Down', 'Tab',
                  'KP_4', 'KP_5', 'KP_6', 'KP_8', 'Next', 'Prior']
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
    for cand in candidates:
        send(cand, 'pressing candidate')
        got = enter_and_read(tail, cand, quiet=True)
        if got is None:
            print(f'    {cand:7s} -> no request (key ignored, or the song failed)')
            continue
        what = []
        if got[0] != base[0]:
            what.append(f'song {base[0]}->{got[0]}')
        if got[1] != base[1]:
            what.append(f'keymode {base[1]}->{got[1]}')
        if got[2] != base[2]:
            what.append(f'levelmode {base[2]}->{got[2]}')
        findings[cand] = what
        print(f'    {cand:7s} -> {", ".join(what) if what else "nothing changed"}')
        base = got              # follow the change so the next key is isolated
    print('\nwhat each candidate key does:')
    for cand, what in findings.items():
        if what:
            print(f'  {cand:7s} -> {", ".join(what)}')
    # map the findings onto the bindings the sweep uses
    discovered = {}
    for cand, what in findings.items():
        for w in what:
            if w.startswith('song '):
                discovered.setdefault('song', []).append(cand)
            if w.startswith('levelmode '):
                discovered.setdefault('levelmode', []).append(cand)
            if w.startswith('keymode '):
                discovered.setdefault('keymode', []).append(cand)
    print('\ninterpretation:')
    for kind, keys in discovered.items():
        print(f'  {kind:10s}: {", ".join(keys)}')
    if not discovered:
        print('  nothing changed — the game may not have been focused, or the'
              ' candidate keys are all wrong for this build')
        return 1
    if 'song' in discovered and len(discovered['song']) >= 2:
        K['next_song'], K['prev_song'] = discovered['song'][-1], discovered['song'][0]
    if 'levelmode' in discovered and len(discovered['levelmode']) >= 2:
        K['next_diff'], K['prev_diff'] = discovered['levelmode'][-1], discovered['levelmode'][0]
    if 'keymode' in discovered:
        K['keymode_next'] = discovered['keymode'][-1]
        K['keymode_prev'] = discovered['keymode'][0]
    print('\nwould set: ' + json.dumps(
        {k: K[k] for k in ('next_song', 'prev_song', 'next_diff', 'prev_diff',
                           'keymode_next', 'keymode_prev')}, ensure_ascii=False))
    if write:
        cfg = json.load(open(KEYS))
        cfg['keys'] = {**cfg.get('keys', {}), **{k: K[k] for k in (
            'next_song', 'prev_song', 'next_diff', 'prev_diff',
            'keymode_next', 'keymode_prev')}}
        json.dump(cfg, open(KEYS, 'w'), indent=1, ensure_ascii=False)
        print(f'wrote {os.path.relpath(KEYS, ROOT)}')
    else:
        print(f'add --write to store it in {os.path.relpath(KEYS, ROOT)}')
    return 0


def enter_and_read(tail, tag, quiet=False):
    """Start a song, return the request it made, then leave via the pause menu."""
    tail.poll()                      # clear
    send(K['enter_song'], None if quiet else f'{tag}: Enter')
    req = tail.wait(T['wait_for_request'])
    if req is None:
        return None                  # never entered — do not send the exit keys
    time.sleep(T['after_start'])     # reach gameplay, so ESC opens PAUSE
    exit_song()
    return (req.get('musicresourcename'), int(req.get('keymode') or 0),
            int(req.get('levelmode') or 0), req.get('gamemode'))


GAMEMODE = {'BASIC': '1', 'STANDARD': '2'}


def last_gamemode():
    """gamemode of the most recent pattern request in the log (mode tracking)."""
    try:
        tail = Tail(LOG)
        reqs = tail.read_all()
        return reqs[-1].get('gamemode') if reqs else None
    except Exception:
        return None


def exit_song():
    """Leave the song via the pause menu and return to the song select.

    ESC opens PAUSE (RESUME focused), Up wraps to MUSIC SELECT, ENTER confirms.
    """
    for key in CFG.get('exit_song', ['Escape', 'Up', 'Return']):
        send(key)
        time.sleep(0.5)
    time.sleep(T['after_exit'])


def goto_mode(target, frm='BASIC'):
    """Step to a mode card by the short way round the ring, then confirm.

    `frm` must be the card that currently has focus. The ring wraps, so the
    direction is chosen by shortest distance; BASIC and STANDARD are adjacent,
    so this is one keypress in practice.
    """
    cards = [c.upper() for c in CFG['menu']['cards']]
    try:
        i, j = cards.index(frm.upper()), cards.index(target.upper())
    except ValueError:
        print(f'  unknown card (known: {", ".join(cards)})')
        return False
    n = len(cards)
    steps, direction = (j - i) % n, 'Right'
    if steps > n - steps:
        steps, direction = n - steps, 'Left'
    print(f'  {frm.upper()} -> {target.upper()}: {steps}x {direction} then '
          f'{CFG["menu"]["confirm"]!r}')
    for _ in range(steps):
        send(direction)
    send(CFG['menu']['confirm'])
    time.sleep(T['after_confirm'])
    return True


def resync():
    """Best effort return to the song select: the exit sequence again."""
    if not game_focused(verbose=True):
        return
    print('  resync: sending the exit sequence')
    for key in CFG.get('resync', ['Escape', 'Up', 'Return']):
        run(['xdotool', 'key', '--clearmodifiers', key])
        time.sleep(0.5)
    time.sleep(T['after_exit'])


def sweep(limit, variants, shot, dry, mode=None):
    tail = Tail(LOG)
    cdn = CdnWatch()
    print(f'{"DRY RUN — " if dry else ""}sweep: up to {limit} entries, '
          f'{len(tail.seen)} requests already in the log')
    print(f'  bindings: enter={K["enter_song"]!r} '
          f'exit={CFG.get("exit_song")} next={K["next_song"]!r} '
          f'song/diff axes: {K["next_song"]}/{K["next_diff"]} '
          f'keymode={K["keymode_next"]!r}')
    if dry:
        print('  would: [shot] Enter -> wait for the request -> wait '
              f'{T["after_start"]}s for gameplay -> Esc/Up/Enter (MUSIC SELECT) '
              '-> next song -> repeat')
        return 0
    if not game_focused(verbose=True):
        return 2
    prev_gm = last_gamemode()
    if mode:
        if not goto_mode(mode, arg(sys.argv[1:], '--from', 'BASIC')):
            return 2
    captured = skipped = failed = 0
    nochart = 0
    # Was a song started and never confirmed-left? Then we are still in it (its
    # gameplay), and only *then* is Escape provably safe: in the main menu ESC is
    # 나가기 (leave), so an unprovoked Escape can walk the game out of song select.
    last_confirmed = False
    try:
        for i in range(limit):
            if shot:
                screenshot(f'{i:04d}_before')
            cdn.baseline()
            send(K['enter_song'], f'[{i+1}/{limit}] enter')
            req = tail.wait(T['wait_for_request'])
            if req is None:
                failed += 1
                recover(last_confirmed, f'{i:04d}_nostart' if shot else None)
                last_confirmed = False
                time.sleep(T['settle'])
                continue
            events = cdn.wait_new(T['wait_for_cdn'])
            ok = [e for e in events if e[0] in ('OK', 'HIT')]
            k = tail.key(req)
            if mode and captured == 0 and prev_gm and k[3] == prev_gm:
                print(f'    WARNING: gamemode is still {k[3]} after switching to '
                      f'{mode.upper()} — the menu step probably missed '
                      f'(check --from / sweep_keys.json menu)')
            if not ok:
                nochart += 1
                print(f'    ASKED BUT NO CHART  {k[0]:24s} km={k[1]} lm={k[2]} '
                      f'gm={k[3]}  (CDN {[e[0] for e in events] or "silent"})')
            elif k in tail.seen:
                skipped += 1
                last_confirmed = True
                print(f'    already known: {k[0]} km={k[1]} lm={k[2]} gm={k[3]}'
                      f'   (CDN {ok[0][0]})')
            else:
                captured += 1
                last_confirmed = True
                tail.seen.add(k)
                progress({'t': int(time.time()), 'song': k[0], 'keymode': k[1],
                          'levelmode': k[2], 'gamemode': k[3], 'cdn': ok[0][0]})
                print(f'    CAPTURED  {k[0]:24s} km={k[1]} lm={k[2]} gm={k[3]}'
                      f'   ({captured} new, CDN {ok[0][0]})')
            if ok:
                # A confirmed start: the game is loading into gameplay, so the
                # pause menu is the right way out.
                time.sleep(T['after_start'])
                exit_song()
                last_confirmed = False
            else:
                # The load failed; the client backs out to the song select by
                # itself (after its 5 retries). Do not press ESC here.
                time.sleep(T['after_failed_load'])
                last_confirmed = False
            if variants:
                for which, key in (('diff', K['next_diff']), ('diff', K['next_diff']),
                                   ('diff', K['next_diff']), ('mode', K['keymode_next'])):
                    send(key, f'  cycle {which}')
                    enter_and_read(tail, which, quiet=True)
            send(K['next_song'], 'next song')
            time.sleep(T['settle'])
    except KeyboardInterrupt:
        print('\ninterrupted')
    print(f'\ndone: {captured} captured, {skipped} already known, '
          f'{nochart} asked-but-no-chart (still missing), {failed} with no request')
    print(f'progress journal: {os.path.relpath(PROGRESS, ROOT)}')
    print('next: python server/_build_data.py && python server/_coverage.py')
    return 0


def main():
    a = sys.argv[1:]
    if '--watch' in a:
        return watch()
    if '--calibrate' in a:
        return calibrate(write='--write' in a)
    if '--state' in a:
        st = screen_state()
        if st is None:
            print('screen classifier unavailable')
            return 1
        print(f'{st[0]}  conf={st[1]:.2f}  ({st[2]})')
        return 0
    mode = arg(a, '--mode', None)
    if '--dry-run' in a:
        return sweep(int(arg(a, '--limit', 10)), '--variants' in a, '--shot' in a,
                     True, mode)
    if not a:
        print(__doc__)
        print(f'sweep keys: {json.dumps(K, ensure_ascii=False)}')
        print(f'focused window right now: {focused_app()!r} '
              f'(game is {CFG["game_app_id"]!r})')
        return 0
    return sweep(int(arg(a, '--limit', 50)), '--variants' in a, '--shot' in a,
                 False, mode)


def arg(a, name, default):
    if name in a:
        return a[a.index(name) + 1]
    return default


if __name__ == '__main__':
    sys.exit(main())
