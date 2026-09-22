#!/usr/bin/env python3
"""Screen-state classifier for the chart sweeper.

Why this is not raw template matching
-------------------------------------
The song-select UI is semi-transparent over an *animated* music video, and the
game blurs that video heavily. So panel interiors change every frame and cannot
be matched pixel-for-pixel. Measured on the real song select:

    ROI (1920x1080)                temporal |frame1-frame2|   mean |grad|
    blurred BGA field                        102                  1.84
    semi-transparent nav pill                 21                  5.44
    opaque yellow play disk                  4.9                  5.34
    static circular BGA preview              4.9                  4.21

Two consequences, and they drive the design:

* **Temporal differencing is useless here** — the background moves, so translucent
  UI moves with it, while the *static* preview looks UI-stable.
* **Structure survives blending.** Because the BGA is blurred, the UI is the only
  high-frequency content, so edge energy separates UI from background even through
  a translucent panel. Saturated, near-opaque accents (the yellow play disk, the
  white key badges, the cyan selection) are additionally reliable by hue: the BGA
  shifts a panel's brightness, not its hue.

So a probe is either an accent-colour blob in a fixed ROI, an edge-energy / edge-
map comparison in a fixed ROI, and never an intensity template of a translucent
panel. `--collect` gathers per-state anchors (edge-grid signatures + accent stats)
and `classify()` combines a few hard rules with nearest-signature matching.

Capture is focus-independent: the game is XWayland, so
`ffmpeg -f x11grab -window_id` reads its pixels without stealing focus. (niri's
`screenshot-window` only captures the *focused* window, and this desktop is
focus-follows-mouse, which makes it unusable while the sweep's terminal is up.)

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


# (x0, y0, x1, y1), all in canonical 1920x1080 coordinates.
ROI = {
    'play':  (580, 640, 760, 800),     # yellow play disk (song select)
    'nav':   (430, 25, 900, 75),       # top nav pill / selected tab
    'list':  (760, 150, 1820, 980),    # song list
    'left':  (40, 560, 720, 1000),     # left stat panels
    'hint':  (760, 935, 1820, 1010),   # bottom hint bar
    'bg':    (900, 60, 1400, 200),     # blurred BGA field (no UI)
    'preview': (300, 180, 560, 420),   # circular BGA preview
}

# PIL 'HSV' is H,S,V in 0..255.
ACCENT = {
    'yellow': ((25, 140, 180), (45, 255, 255)),
    'cyan':   ((110, 120, 150), (150, 255, 255)),
    'white':  ((0, 0, 225), (255, 45, 255)),
}

# Hard rules evaluated before nearest-signature matching. Each is
# (state, feature, min, max) on a scalar feature.
RULES = [
    ('SONG_SELECT', 'play_yellow', 1200, 10 ** 9),
]


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
def edge_mag(gray):
    """Mean-abs gradient; large where the (sharp) UI is, small on the blurred BGA."""
    gx = np.zeros_like(gray)
    gy = np.zeros_like(gray)
    gx[:, 1:] = np.abs(gray[:, 1:] - gray[:, :-1])
    gy[1:, :] = np.abs(gray[1:, :] - gray[:-1, :])
    return gx + gy


def coarse(em, nx=16, ny=9):
    """A small edge-energy fingerprint of the whole frame (UI layout signature)."""
    h, w = em.shape
    ys = np.linspace(0, h, ny + 1).astype(int)
    xs = np.linspace(0, w, nx + 1).astype(int)
    g = np.empty((ny, nx), np.float32)
    for j in range(ny):
        for i in range(nx):
            g[j, i] = em[ys[j]:ys[j + 1], xs[i]:xs[i + 1]].mean()
    return g


def _roi_slice(roi, shape):
    x0, y0, x1, y1 = roi
    h, w = shape[:2]
    return slice(min(y0, h), min(y1, h)), slice(min(x0, w), min(x1, w))


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
    """Feature dict for one frame. Pure numpy/PIL, a few ms per frame."""
    im = Image.fromarray(rgb)
    hsv = np.asarray(im.convert('HSV')).astype(np.int16)
    H, S, V = hsv[..., 0], hsv[..., 1], hsv[..., 2]
    em = edge_mag(np.asarray(im.convert('L')).astype(np.float32))

    masks = {}
    for name, (lo, hi) in ACCENT.items():
        masks[name] = ((H >= lo[0]) & (H <= hi[0]) &
                       (S >= lo[1]) & (S <= hi[1]) &
                       (V >= lo[2]) & (V <= hi[2]))

    feats = {'size': [rgb.shape[1], rgb.shape[0]]}
    for name, roi in ROI.items():
        feats[f'edge_{name}'] = round(float(em[_roi_slice(roi, em.shape)].mean()), 3)
    for name, roi in (('play_yellow', ROI['play']), ('nav_white', ROI['nav']),
                      ('list_cyan', ROI['list'])):
        n, centroid, bbox = _blob(masks[name.split('_')[1]], roi)
        feats[name] = n
        feats[name + '_centroid'] = centroid
        feats[name + '_bbox'] = bbox
    feats['mean_v'] = round(float(V.mean()), 2)
    feats['edge_grid'] = [round(float(x), 3) for x in coarse(em).ravel()]
    return feats


# ---------------------------------------------------------------- classify
def _corr(a, b):
    a = np.asarray(a, np.float32)
    b = np.asarray(b, np.float32)
    a = a - a.mean()
    b = b - b.mean()
    d = float(np.linalg.norm(a) * np.linalg.norm(b))
    return float((a @ b) / d) if d else 0.0


def load_anchors():
    """{state: [feature dict, ...]} from server/anchors/<state>/*.json."""
    out = {}
    if not os.path.isdir(ANCHORS):
        return out
    for state in sorted(os.listdir(ANCHORS)):
        d = os.path.join(ANCHORS, state)
        if not os.path.isdir(d):
            continue
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


def classify(feats, anchors=None):
    """(state, confidence, why). Rules first, then nearest signature by edge-grid corr."""
    for state, key, lo, hi in RULES:
        v = feats.get(key, 0)
        if lo <= v <= hi:
            return state, 1.0, f'{key}={v}'
    anchors = anchors if anchors is not None else load_anchors()
    best = ('UNKNOWN', 0.0, 'no rule fired and no anchors collected')
    for state, items in anchors.items():
        for a in items:
            c = _corr(feats['edge_grid'], a['edge_grid'])
            if c > best[1]:
                best = (state, c, f'edge-grid corr {c:.3f}')
    if best[1] < 0.9:
        return 'UNKNOWN', best[1], best[2]
    return best


# ---------------------------------------------------------------- rendering
def annotate(rgb, feats, state, conf, why):
    im = Image.fromarray(rgb).convert('RGB')
    dr = ImageDraw.Draw(im)
    for name, roi in ROI.items():
        colour = (255, 60, 60) if name in ('play', 'nav', 'hint') else (90, 180, 255)
        dr.rectangle(roi, outline=colour, width=2)
        dr.text((roi[0] + 4, roi[1] + 4), name, fill=colour)
    bbox = feats.get('play_yellow_bbox')
    if bbox:
        dr.rectangle(bbox, outline=(255, 255, 0), width=3)
    dr.rectangle((0, 0, 620, 30), fill=(0, 0, 0))
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
    a = sys.argv[1:]
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--window-id', type=int, help='X11 window id (default: search EZ2ON)')
    ap.add_argument('--debug', action='store_true', help='print features, save an annotated frame')
    ap.add_argument('--json', action='store_true', help='print the raw feature vector')
    ap.add_argument('--collect', metavar='STATE', help='save the current frame as an anchor')
    ap.add_argument('--list', action='store_true', help='list collected anchors')
    ap.add_argument('--watch', action='store_true', help='classify continuously')
    ap.add_argument('--interval', type=float, default=1.0, help='watch poll interval')
    ap.add_argument('--out', default=os.path.join(SHOTS, 'annotated.png'))
    args = ap.parse_args(a)

    if args.list:
        anchors = load_anchors()
        if not anchors:
            print(f'no anchors yet under {os.path.relpath(ANCHORS, ROOT)}')
        for state, items in anchors.items():
            print(f'  {state:16s} {len(items)} frame(s)')
        return 0

    if args.watch:
        anchors = load_anchors()
        last = None
        print('watching (Ctrl-C to stop)...')
        try:
            while True:
                try:
                    rgb = grab(args.window_id)
                    f = analyze(rgb)
                    state, conf, why = classify(f, anchors)
                except Exception as e:
                    print(f'  grab failed: {e}')
                    time.sleep(args.interval)
                    continue
                if state != last:
                    print(f'  {time.strftime("%H:%M:%S")}  {state}  '
                          f'conf={conf:.2f}  {why}  (play_yellow={f["play_yellow"]})')
                    last = state
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print('\nstopped')
        return 0

    rgb = grab(args.window_id)
    f = analyze(rgb)
    state, conf, why = classify(f)
    if args.json:
        print(json.dumps(f, indent=1))
    if args.collect:
        save_collect(rgb, args.collect, f)
    if args.debug or not (args.json or args.collect):
        os.makedirs(SHOTS, exist_ok=True)
        annotate(rgb, f, state, conf, why).save(args.out)
        print(f'state={state}  conf={conf:.2f}  ({why})')
        for k in ('play_yellow', 'play_yellow_centroid', 'nav_white', 'list_cyan',
                  'mean_v', 'edge_play', 'edge_nav', 'edge_list', 'edge_left',
                  'edge_hint', 'edge_bg', 'edge_preview'):
            print(f'  {k:22s} {f[k]}')
        print(f'annotated -> {os.path.relpath(args.out, ROOT)}')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ScreenError, OSError, subprocess.SubprocessError) as e:
        sys.exit(f'error: {e}')
