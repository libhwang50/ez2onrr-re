#!/usr/bin/env python3
"""Screen-state classifier for the chart sweeper.

Why this is not raw template matching, and not OCR
--------------------------------------------------
The song-select UI is semi-transparent over an *animated* music video, and the game
blurs that video heavily. Measured on the real screen at 1920x1080:

    ROI                          temporal |f1-f2|    mean |grad|
    blurred BGA field                 102              1.84
    semi-transparent nav pill          21              5.44
    opaque yellow play disk           4.9              5.34
    static circular preview           4.9              4.21

So temporal differencing is useless (the background moves, so translucent UI moves with
it, while the *static* preview looks UI-stable). Two things do work:

* **Saturated, near-opaque accents** by hue (the yellow play disk, red GAME OVER banner,
  cyan selections) — the BGA shifts a panel's brightness, not its hue.
* **Localized edge structure.** The BGA is blurred, so the UI is the only high-frequency
  content, and edge correlation survives alpha blending. It must be *localized*: a
  whole-frame edge signature is dominated by chrome every screen shares (the top nav,
  the bottom hint bar), so global matching collides across screens. Restricting to
  screen-unique regions separates them cleanly — measured max cross-state correlation:
  `center` 0.10, `upperleft` 0.19, versus `top`/`nav`/`hint` ~0.99.

`classify()` therefore applies a few scalar rules (accent colour, darkness, redness)
and then falls back to nearest-match over localized edge probes of the collected
`server/anchors/<STATE>/` frames.

Capture is focus-independent: the game is XWayland, so `ffmpeg -f x11grab -window_id`
reads its pixels without stealing focus. (niri's `screenshot-window` only captures the
*focused* window, and this desktop is focus-follows-mouse, which makes it unusable while
the sweep's terminal is up.)

Usage
-----
    python server/_screen.py --debug                 # features + annotated ROI map
    python server/_screen.py --json                  # one feature vector
    python server/_screen.py --collect SONG_SELECT   # save an anchor for a state
    python server/_screen.py --watch                 # classify continuously
    python server/_screen.py --list                  # show collected anchors

The game window is found with `xdotool search --name '^EZ2ON$'`; override with
`--window-id N` or `EZ2_WINDOW_ID`.
"""
import argparse
import json
import os
import subprocess
import sys
import time

import numpy as np
from PIL import Image, ImageDraw

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.path.join(ROOT, 'server', 'shots')
ANCHORS = os.path.join(ROOT, 'server', 'anchors')
GAME_TITLE = os.environ.get('EZ2_GAME_TITLE', '^EZ2ON$')

CANON = (1920, 1080)


class ScreenError(RuntimeError):
    """Raised when the game window cannot be found or captured."""


# Fixed regions of interest, all in canonical 1920x1080 coordinates.
ROI = {
    'play':  (580, 640, 760, 800),     # yellow play disk (song select)
    'nav':   (430, 25, 900, 75),       # top nav pill / selected tab
    'list':  (760, 150, 1820, 980),    # song list
    'left':  (40, 560, 720, 1000),     # left stat panels
    'hint':  (760, 935, 1820, 1010),   # bottom hint bar
    'bg':    (900, 60, 1400, 200),     # blurred BGA field (no UI)
    'preview': (300, 180, 560, 420),   # circular BGA preview
}

# Regions used for edge-probe matching. Only screen-unique regions belong here: the
# shared chrome (nav, hint bar) correlates ~0.99 between every screen and would drown
# out the differences.
PROBES = {
    'center':    (600, 100, 1320, 330),   # pause wordmark / GAME OVER banner / card art
    'upperleft': (0, 0, 640, 560),        # mode cards / playfield / stat panels
}

# PIL 'HSV' is H,S,V in 0..255.
ACCENT = {
    'yellow': ((25, 140, 180), (45, 255, 255)),
    'cyan':   ((110, 120, 150), (150, 255, 255)),
    'white':  ((0, 0, 225), (255, 45, 255)),
    'red':    ((0, 110, 70), (18, 255, 255)),
}

PROBE_MIN = 0.5       # minimum correlation to accept an edge-probe match
PROBE_MARGIN = 0.15   # required lead over the runner-up state


# ---------------------------------------------------------------- capture
def _run(cmd, timeout=20):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def window_id():
    wid = os.environ.get('EZ2_WINDOW_ID')
    if wid:
        return int(wid)
    r = _run(['xdotool', 'search', '--name', GAME_TITLE])
    ids = [int(x) for x in r.stdout.split()]
    if not ids:
        raise ScreenError(f'no window matching {GAME_TITLE!r} (is the game running?)')
    return ids[0]


def window_geometry(wid):
    r = _run(['xdotool', 'getwindowgeometry', '--shell', str(wid)])
    vals = dict(line.split('=', 1) for line in r.stdout.splitlines() if '=' in line)
    if 'WIDTH' not in vals or 'HEIGHT' not in vals:
        raise ScreenError(f'cannot read geometry of window {wid}: '
                          f'{(r.stderr or r.stdout).strip()[:120]}')
    return int(vals['WIDTH']), int(vals['HEIGHT'])


def grab(wid=None, timeout=8.0):
    """One RGB frame of the game window, as a uint8 HxWx3 array. Focus-independent."""
    wid = wid or window_id()
    w, h = window_geometry(wid)
    cmd = ['ffmpeg', '-hide_banner', '-loglevel', 'error',
           '-f', 'x11grab', '-window_id', str(wid),
           '-i', os.environ.get('DISPLAY', ':0'),
           '-frames:v', '1', '-f', 'rawvideo', '-pix_fmt', 'rgb24', '-']
    p = subprocess.run(cmd, capture_output=True, timeout=timeout)
    need = w * h * 3
    if len(p.stdout) < need:
        raise ScreenError(f'x11grab returned {len(p.stdout)}B, expected {need} '
                          f'({w}x{h}); stderr: {p.stderr.decode()[:200]}')
    return np.frombuffer(p.stdout[:need], np.uint8).reshape(h, w, 3)


# ---------------------------------------------------------------- features
def edge_map(gray):
    """Mean-abs gradient; large where the (sharp) UI is, small on the blurred BGA."""
    gx = np.zeros_like(gray)
    gy = np.zeros_like(gray)
    gx[:, 1:] = np.abs(gray[:, 1:] - gray[:, :-1])
    gy[1:, :] = np.abs(gray[1:, :] - gray[:-1, :])
    return gx + gy


def edge_map_rgb(rgb):
    return edge_map(np.asarray(Image.fromarray(rgb).convert('L')).astype(np.float32))


def _roi_slice(roi, shape):
    x0, y0, x1, y1 = roi
    h, w = shape[:2]
    return slice(min(y0, h), min(y1, h)), slice(min(x0, w), min(x1, w))


def patch_vec(em, roi):
    """Mean-subtracted edge patch of one ROI, flattened (for correlation)."""
    sub = em[_roi_slice(roi, em.shape)].astype(np.float32)
    return (sub - sub.mean()).ravel()


def _blob(mask, roi):
    sub = mask[_roi_slice(roi, mask.shape)]
    n = int(sub.sum())
    if not n:
        return 0, None, None
    ys, xs = np.where(sub)
    x0, y0, _x1, _y1 = roi
    cx, cy = int(xs.mean()) + x0, int(ys.mean()) + y0
    return n, (cx, cy), (int(xs.min()) + x0, int(ys.min()) + y0,
                         int(xs.max()) + x0, int(ys.max()) + y0)


def analyze(rgb):
    """Feature dict for one frame: scalar features + accent blobs (JSON-serializable)."""
    im = Image.fromarray(rgb)
    hsv = np.asarray(im.convert('HSV')).astype(np.int16)
    H, S, V = hsv[..., 0], hsv[..., 1], hsv[..., 2]
    em = edge_map(np.asarray(im.convert('L')).astype(np.float32))

    masks = {}
    for name, (lo, hi) in ACCENT.items():
        masks[name] = ((H >= lo[0]) & (H <= hi[0]) &
                       (S >= lo[1]) & (S <= hi[1]) &
                       (V >= lo[2]) & (V <= hi[2]))

    feats = {
        'size': [rgb.shape[1], rgb.shape[0]],
        'mean_v': round(float(V.mean()), 2),
        'dark_pct': round(float((V < 35).mean()) * 100, 2),
        'bright_pct': round(float((V > 200).mean()) * 100, 2),
        'red_pct': round(float(masks['red'].mean()) * 100, 3),
        'cyan_pct': round(float(masks['cyan'].mean()) * 100, 3),
        'white_pct': round(float(masks['white'].mean()) * 100, 3),
    }
    for name, roi in ROI.items():
        feats[f'edge_{name}'] = round(float(em[_roi_slice(roi, em.shape)].mean()), 3)
    for name, roi in (('play_yellow', ROI['play']), ('nav_white', ROI['nav']),
                      ('list_cyan', ROI['list'])):
        n, centroid, bbox = _blob(masks[name.split('_')[1]], roi)
        feats[name] = n
        feats[name + '_centroid'] = centroid
        feats[name + '_bbox'] = bbox
    return feats


# ---------------------------------------------------------------- anchors
def anchor_dirs():
    if not os.path.isdir(ANCHORS):
        return []
    return [(s, os.path.join(ANCHORS, s)) for s in sorted(os.listdir(ANCHORS))
            if os.path.isdir(os.path.join(ANCHORS, s))]


def load_anchors():
    """{state: [feature dict, ...]} from server/anchors/<state>/*.json."""
    out = {}
    for state, d in anchor_dirs():
        items = []
        for fn in sorted(os.listdir(d)):
            if fn.endswith('.json'):
                try:
                    items.append(json.load(open(os.path.join(d, fn))))
                except ValueError:
                    pass
        if items:
            out[state] = items
    return out


_patch_cache = None


def load_anchor_patches():
    """{state: [ {probe: edge patch} ]} from the anchor PNGs (cached)."""
    global _patch_cache
    if _patch_cache is not None:
        return _patch_cache
    out = {}
    for state, d in anchor_dirs():
        sigs = []
        for fn in sorted(os.listdir(d)):
            if not fn.endswith('.png'):
                continue
            try:
                rgb = np.asarray(Image.open(os.path.join(d, fn)).convert('RGB'))
            except OSError:
                continue
            em = edge_map_rgb(rgb)
            sigs.append({name: patch_vec(em, roi) for name, roi in PROBES.items()})
        if sigs:
            out[state] = sigs
    _patch_cache = out
    return out


def _corr(a, b):
    a = np.asarray(a, np.float32)
    b = np.asarray(b, np.float32)
    d = float(np.linalg.norm(a) * np.linalg.norm(b))
    return float((a @ b) / d) if d else 0.0


# ---------------------------------------------------------------- classify
def _rule(f):
    """Strong, measured scalar rules. Each returns (state, conf, why) or None.

    Order matters: a red-heavy BGA during gameplay must hit the darkness check before
    the redness one, so GAMEPLAY is tested first (a real GAME_OVER is dimmed but not
    black: measured dark_pct 45 vs 88 for gameplay).
    """
    if f['play_yellow'] > 1200:
        return 'SONG_SELECT', 1.0, f"play_yellow={f['play_yellow']}"
    if f['dark_pct'] > 60.0:
        return 'GAMEPLAY', 1.0, f"dark_pct={f['dark_pct']:.1f}"
    if f['red_pct'] > 15.0:
        return 'GAME_OVER', 1.0, f"red_pct={f['red_pct']:.1f}"
    return None


def classify(rgb, anchors=None):
    """(state, confidence, why) for one RGB frame.

    Scalar rules first (accent/darkness/redness), then nearest match over the
    localized edge probes of the collected anchors.
    """
    f = analyze(rgb)
    hit = _rule(f)
    if hit:
        return hit

    anchors = load_anchor_patches() if anchors is None else anchors
    if not anchors:
        return 'UNKNOWN', 0.0, 'no rule fired and no anchors collected'

    em = edge_map_rgb(rgb)
    live = {name: patch_vec(em, roi) for name, roi in PROBES.items()}
    scores = {}
    for state, sigs in anchors.items():
        best = -1.0
        for sig in sigs:
            for name in PROBES:
                best = max(best, _corr(live[name], sig[name]))
        scores[state] = best

    order = sorted(scores.items(), key=lambda kv: -kv[1])
    top = order[0]
    second = order[1] if len(order) > 1 else ('', -1.0)
    if top[1] >= PROBE_MIN and (top[1] - second[1]) >= PROBE_MARGIN:
        return top[0], top[1], (f'edge-probe {top[1]:.3f} '
                                f'(next {second[0]} {second[1]:.3f})')
    return 'UNKNOWN', max(top[1], 0.0), (f'best {top[0]} {top[1]:.3f} '
                                         f'below threshold {PROBE_MIN}')


# ---------------------------------------------------------------- rendering
def annotate(rgb, feats, state, conf, why):
    im = Image.fromarray(rgb).convert('RGB')
    dr = ImageDraw.Draw(im)
    for name, roi in {**ROI, **{f'probe:{k}': v for k, v in PROBES.items()}}.items():
        colour = (255, 200, 0) if name.startswith('probe') else (90, 180, 255)
        dr.rectangle(roi, outline=colour, width=2)
        dr.text((roi[0] + 4, roi[1] + 4), name, fill=colour)
    bbox = feats.get('play_yellow_bbox')
    if bbox:
        dr.rectangle(bbox, outline=(255, 255, 0), width=3)
    dr.rectangle((0, 0, 700, 30), fill=(0, 0, 0))
    dr.text((8, 8), f'{state}  conf={conf:.2f}  ({why})', fill=(255, 255, 0))
    return im


def save_collect(rgb, state, feats):
    d = os.path.join(ANCHORS, state)
    os.makedirs(d, exist_ok=True)
    stamp = time.strftime('%Y%m%d-%H%M%S')
    png = os.path.join(d, f'{stamp}.png')
    Image.fromarray(rgb).save(png)
    json.dump(feats, open(os.path.join(d, f'{stamp}.json'), 'w'), indent=1)
    print(f'collected {state}: {os.path.relpath(png, ROOT)}')


# ---------------------------------------------------------------- cli
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--window-id', type=int, help='X11 window id (default: search EZ2ON)')
    ap.add_argument('--debug', action='store_true', help='print features, save an annotated frame')
    ap.add_argument('--json', action='store_true', help='print the raw feature vector')
    ap.add_argument('--collect', metavar='STATE', help='save the current frame as an anchor')
    ap.add_argument('--list', action='store_true', help='list collected anchors')
    ap.add_argument('--check', action='store_true',
                    help='classify every anchor, and with its own state\'s anchors removed')
    ap.add_argument('--watch', action='store_true', help='classify continuously')
    ap.add_argument('--interval', type=float, default=1.0, help='watch poll interval')
    ap.add_argument('--out', default=os.path.join(SHOTS, 'annotated.png'))
    args = ap.parse_args(sys.argv[1:])

    if args.list:
        anchors = load_anchors()
        if not anchors:
            print(f'no anchors yet under {os.path.relpath(ANCHORS, ROOT)}')
        for state, items in anchors.items():
            print(f'  {state:16s} {len(items)} frame(s)')
        return 0

    if args.check:
        anchors = load_anchor_patches()
        if not anchors:
            print(f'no anchors under {os.path.relpath(ANCHORS, ROOT)}')
            return 1
        print('anchors:', {k: len(v) for k, v in anchors.items()})
        print('  `full` should name the state; `without-own-state` should be UNKNOWN '
              '(or a rule hit) — never a different state')
        bad = 0
        for state, d in anchor_dirs():
            for fn in sorted(os.listdir(d)):
                if not fn.endswith('.png'):
                    continue
                rgb = np.asarray(Image.open(os.path.join(d, fn)).convert('RGB'))
                full = classify(rgb, anchors=anchors)
                loo = classify(rgb, anchors={k: v for k, v in anchors.items()
                                             if k != state})
                miss = full[0] != state
                bad += miss
                print(f'  {state:12s} {fn:20s} full={full[0]:12s} ({full[1]:.2f})  '
                      f'without-own-state={loo[0]:12s} ({loo[1]:.2f})  '
                      f'{"MISS" if miss else "OK"}')
        print(f'\n{len(anchors)} state(s), {bad} miss(es)')
        return 1 if bad else 0

    if args.watch:
        global _patch_cache
        last = None
        print('watching (Ctrl-C to stop)...')
        try:
            while True:
                try:
                    rgb = grab(args.window_id)
                    _patch_cache = None          # pick up anchors collected meanwhile
                    state, conf, why = classify(rgb)
                except (ScreenError, OSError, subprocess.SubprocessError) as e:
                    print(f'  grab failed: {e}')
                    time.sleep(args.interval)
                    continue
                if state != last:
                    f = analyze(rgb)
                    print(f'  {time.strftime("%H:%M:%S")}  {state}  conf={conf:.2f}  '
                          f'{why}  (dark={f["dark_pct"]} red={f["red_pct"]} '
                          f'play={f["play_yellow"]})')
                    last = state
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print('\nstopped')
        return 0

    rgb = grab(args.window_id)
    f = analyze(rgb)
    state, conf, why = classify(rgb)

    if args.json:
        print(json.dumps(f, indent=1))
    if args.collect:
        save_collect(rgb, args.collect, f)
    if args.debug or not (args.json or args.collect):
        os.makedirs(SHOTS, exist_ok=True)
        annotate(rgb, f, state, conf, why).save(args.out)
        print(f'state={state}  conf={conf:.2f}  ({why})')
        for k in ('play_yellow', 'play_yellow_centroid', 'nav_white', 'list_cyan',
                  'mean_v', 'dark_pct', 'bright_pct', 'red_pct', 'cyan_pct', 'white_pct',
                  'edge_play', 'edge_nav', 'edge_hint', 'edge_left', 'edge_bg'):
            print(f'  {k:22s} {f[k]}')
        print(f'annotated -> {os.path.relpath(args.out, ROOT)}')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ScreenError, OSError, subprocess.SubprocessError) as e:
        sys.exit(f'error: {e}')
