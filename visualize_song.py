#!/usr/bin/env python3
"""Render a video visualisation of a song, showing which keysounds are playing.

The song is a render of the chart (see AGENTS.md 3.5), so at any instant the audio is the
sum of the keysounds whose notes are firing. This draws that as an overlay on the song's
BGA — or on a plain background — and muxes it with the rendered audio.

    python3 visualize_song.py extracted_charts/destr0yer -o destr0yer.mp4
    python3 visualize_song.py <song> --bga extracted_assets/rebind/Rebind.mp4
    python3 visualize_song.py <song> --size 1920x1080 --fps 30 --render

Layout: a top bar with the title/variant/composer and a progress bar, a lane row that lights
as each lane fires, and a ticker of the most recent keysounds with their lane and time.

The overlay is produced as RGBA frames piped straight into ffmpeg, which composites it over
the background and muxes the audio in one pass. Without --render an existing
rendered_songs/<song>.flac is used; with it, or if none exists, the song is rendered first.

Requires Pillow and ffmpeg.
"""
import argparse
import collections
import json
import os
import re
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import song_meta  # noqa: E402
from parse_chart import parse_ez, parse_ezi, load  # noqa: E402

MONO_CANDIDATES = (
    '/usr/share/fonts/noto/NotoSansMono-Bold.ttf',
    '/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf',
    '/usr/share/fonts/noto/NotoSansMono-Regular.ttf',
    '/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',
)

LANE_TRACK = range(3, 22)          # tracks that can be a playable lane
TICKER_ROWS = 10


def font(size):
    for p in MONO_CANDIDATES:
        if os.path.exists(p):
            try:
                return ImageFont.truetype(p, size)
            except Exception:
                pass
    return ImageFont.load_default()


def parse_size(s):
    m = re.match(r'^(\d+)x(\d+)$', s)
    if not m:
        raise argparse.ArgumentTypeError('expected WxH, e.g. 1280x720')
    return int(m.group(1)), int(m.group(2))


def chart_label(song_dir):
    try:
        return (json.load(open(os.path.join(song_dir, 'ident.json'))) or {}).get('label') or {}
    except (OSError, ValueError):
        return {}


def build_events(song_dir, assets_root='extracted_assets'):
    """[(seconds, track, keysound, filename, is_long)] for every note, in time order."""
    ch = parse_ez(load(os.path.join(song_dir, 'ez.ez'))[0])
    insts = parse_ezi(load(os.path.join(song_dir, 'ezi.ezi'))[0])
    names = {i.index: i.filename for i in insts}
    out = [(sec, track, n.keysound, names.get(n.keysound, ''), n.is_long)
           for sec, track, n in ch.note_seconds()]
    return ch, out, names


def find_bga(song_dir, assets_root='extracted_assets'):
    """A BGA .mp4 for this song, if one has been extracted."""
    stems = set()
    try:
        insts = parse_ezi(load(os.path.join(song_dir, 'ezi.ezi'))[0])
        stems = {os.path.splitext(i.filename)[0].lower() for i in insts}
    except Exception:
        pass
    best = None
    for name in sorted(os.listdir(assets_root)) if os.path.isdir(assets_root) else []:
        d = os.path.join(assets_root, name)
        if not os.path.isdir(d):
            continue
        vids = [f for f in os.listdir(d) if f.lower().endswith(('.mp4', '.webm'))]
        if not vids:
            continue
        # prefer the assets dir whose keysounds look like this chart's
        have = {os.path.splitext(f)[0].lower() for f in os.listdir(d)}
        score = len(stems & have) / float(max(1, len(stems)))
        if score > 0.9 and (best is None or os.path.getsize(os.path.join(d, vids[0])) > best[0]):
            best = (os.path.getsize(os.path.join(d, vids[0])), os.path.join(d, vids[0]))
    return best[1] if best else None


def render_audio(song_dir, out, assets='auto'):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import render_song
    return render_song.render_one(song_dir, assets, out)


def draw_frame(img, dr, state):
    """Draw one overlay frame. Everything is semi-transparent so the BGA shows through."""
    W, H, f = state['W'], state['H'], state
    pad = 18
    t = state['t']

    # ---- top bar ---------------------------------------------------------- #
    bar = int(H * 0.12)
    dr.rectangle([0, 0, W, bar], fill=(6, 8, 14, 205))
    dr.text((pad, pad - 4), state['title'], font=state['f_title'], fill=(240, 244, 252, 255))
    sub = '  '.join(x for x in (state['variant'], state['composer']) if x)
    dr.text((pad, pad + state['f_title'].size + 4), sub, font=state['f_small'],
            fill=(150, 200, 255, 235))
    dr.text((W - pad, pad - 2), state['clock'], font=state['f_title'],
            fill=(240, 244, 252, 255), anchor='ra')
    dr.text((W - pad, pad + state['f_title'].size + 6), '%d keysounds' % state['n_keys'],
            font=state['f_small'], fill=(150, 200, 255, 235), anchor='ra')

    # progress bar
    y = bar - 6
    dr.rectangle([0, y, W, bar], fill=(30, 36, 50, 220))
    dr.rectangle([0, y, int(W * state['progress']), bar], fill=(90, 200, 140, 255))

    # ---- lane row --------------------------------------------------------- #
    lanes = state['lanes']
    if lanes:
        bw = min(96, (W - 2 * pad) // max(1, len(lanes)) - 8)
        y0 = bar + 16
        for i, track in enumerate(lanes):
            x = pad + i * (bw + 8)
            lit = track in state['active_tracks']
            dr.rectangle([x, y0, x + bw, y0 + 34],
                         fill=(90, 200, 140, 235) if lit else (22, 26, 38, 200),
                         outline=(70, 80, 100, 235), width=2)
            label = 'K%d' % (i + 1) if i < 8 else 'T%d' % track
            dr.text((x + bw / 2, y0 + 17), label, font=state['f_small'],
                    fill=(10, 14, 20, 255) if lit else (140, 150, 170, 255), anchor='mm')

    # ---- keysound ticker -------------------------------------------------- #
    rows = state['ticker']
    row_h = state['f_mono'].size + 8
    panel_h = row_h * TICKER_ROWS + 2 * pad
    top = H - panel_h
    dr.rectangle([0, top, W, H], fill=(6, 8, 14, 220))
    dr.text((pad, top + 8), 'keysounds', font=state['f_small'], fill=(150, 200, 255, 235))
    for i, ev in enumerate(reversed(rows)):
        sec, track, ks, fname, is_long = ev
        age = t - sec
        alpha = 255 if age < 0.25 else max(70, int(255 - 150 * min(1.0, age / 1.2)))
        yy = top + pad + 14 + i * row_h
        if yy > H - row_h:
            break
        lane = ('lane%d' % (track - 3)) if track in LANE_TRACK else ('T%d' % track)
        dr.text((pad, yy), '%7.2f  %-6s %5d' % (sec, lane, ks), font=state['f_mono'],
                fill=(230, 235, 245, alpha))
        nm = fname or '(unknown)'
        if is_long:
            nm += '   [long]'
        dr.text((pad + 26 * (state['f_mono'].size // 12), yy), nm, font=state['f_mono'],
                fill=(120, 220, 170, alpha) if not is_long else (250, 210, 120, alpha))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('song_dir', help='capture directory holding ez.ez and ezi.ezi')
    ap.add_argument('-o', '--out', help='output mp4 (default visualizations/<song>.mp4)')
    ap.add_argument('--size', type=parse_size, default=(1280, 720))
    ap.add_argument('--fps', type=int, default=30)
    ap.add_argument('--bga', help='BGA video to composite onto (default: auto-detect)')
    ap.add_argument('--no-bga', action='store_true', help='plain background only')
    ap.add_argument('--audio', help='rendered audio to mux (default: reuse or render one)')
    ap.add_argument('--assets', default='auto', help="keysound dir for rendering ('auto')")
    ap.add_argument('--render', action='store_true', help='always re-render the audio')
    ap.add_argument('--crf', type=int, default=20, help='x264 quality (lower is better)')
    ap.add_argument('--preset', default='veryfast')
    ap.add_argument('--until', type=float, help='stop at this many seconds (for testing)')
    args = ap.parse_args()

    W, H = args.size
    song = os.path.basename(os.path.normpath(args.song_dir))
    out = args.out or os.path.join('visualizations', '%s.mp4' % song)
    outdir = os.path.dirname(out)
    if outdir:
        os.makedirs(outdir, exist_ok=True)

    ch, events, names = build_events(args.song_dir)
    if not events:
        sys.exit('%s has no notes' % args.song_dir)
    duration = max(ch.duration, max(e[0] for e in events) + 0.5)
    if args.until:
        duration = min(duration, args.until)

    label = chart_label(args.song_dir)
    title = label.get('title') or label.get('song') or song
    composer = label.get('composer') or ''
    variant = ' '.join(x for x in (label.get('keymode'), label.get('difficulty')) if x)

    # ---- audio ------------------------------------------------------------ #
    audio = args.audio
    if args.render or not audio:
        default = os.path.join('rendered_songs', song + '.flac')
        if not args.render and os.path.exists(default):
            audio = default
        else:
            audio = '/tmp/_viz_%s.flac' % song
            print('rendering audio -> %s' % audio)
            render_audio(args.song_dir, audio, args.assets)

    # Match the video to the audio actually rendered: the chart can run a few seconds past
    # the last note (Conflict by ~6 s), and ending at the chart length leaves a silent tail
    # with a frozen BGA.
    try:
        import soundfile as sf
        adur = sf.info(audio).duration
        if adur and adur > 1.0:
            duration = min(duration, adur)
    except Exception:
        pass

    # ---- background ------------------------------------------------------- #
    bga = None if args.no_bga else (args.bga or find_bga(args.song_dir))
    n_frames = int(duration * args.fps) + 1

    cmd = ['ffmpeg', '-y', '-loglevel', 'error',
           '-f', 'rawvideo', '-pix_fmt', 'rgba', '-s', '%dx%d' % (W, H),
           '-r', str(args.fps), '-i', '-']
    if bga:
        print('background: %s' % bga)
        cmd += ['-i', bga]
    else:
        cmd += ['-f', 'lavfi', '-i', 'color=c=0x0b0d12:s=%dx%d:r=%d:d=%.3f'
                % (W, H, args.fps, duration)]
    cmd += ['-i', audio]
    cmd += ['-filter_complex',
            '[1:v]scale=%d:%d:force_original_aspect_ratio=increase,crop=%d:%d,setsar=1[bg];'
            '[bg][0:v]overlay=0:0,format=yuv420p[v]' % (W, H, W, H),
            '-map', '[v]', '-map', '2:a', '-r', str(args.fps),
            '-c:v', 'libx264', '-preset', args.preset,
            '-crf', str(args.crf), '-c:a', 'aac', '-b:a', '192k',
            '-t', '%.3f' % duration, out]

    f_title, f_small, f_mono = font(max(18, H // 30)), font(max(12, H // 55)), font(max(11, H // 62))
    lanes = sorted({t for _s, t, _k, _f, _l in events if t in LANE_TRACK})
    state = dict(W=W, H=H, title=title, composer=composer, variant=variant,
                 f_title=f_title, f_small=f_small, f_mono=f_mono, lanes=lanes,
                 n_keys=len(names), ticker=collections.deque(maxlen=TICKER_ROWS),
                 active_tracks=set(), lane_lit={}, t=0.0, progress=0.0,
                 clock='0:00 / %d:%02d' % divmod(int(duration), 60))

    print('rendering %d frames at %dx%d @ %d fps (%.1fs) -> %s'
          % (n_frames, W, H, args.fps, duration, out))
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    img = Image.new('RGBA', (W, H), (0, 0, 0, 0))
    dr = ImageDraw.Draw(img, 'RGBA')
    ev_i = 0
    try:
        for fi in range(n_frames):
            t = fi / float(args.fps)
            # advance the event pointer, collecting what is now sounding
            state['active_tracks'] = set()
            while ev_i < len(events) and events[ev_i][0] <= t:
                ev = events[ev_i]
                state['ticker'].append(ev)
                state['active_tracks'].add(ev[1])
                ev_i += 1
            state['t'] = t
            state['progress'] = min(1.0, t / duration) if duration else 0.0
            state['clock'] = '%d:%02d / %d:%02d' % (
                (int(t) // 60, int(t) % 60) + divmod(int(duration), 60))
            img.paste((0, 0, 0, 0), (0, 0, W, H))
            draw_frame(img, dr, state)
            proc.stdin.write(img.tobytes())
            if fi % (args.fps * 10) == 0:
                print('  %5.1f%%  %s' % (100.0 * fi / n_frames, state['clock']), flush=True)
    except BrokenPipeError:
        pass
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait()
    if proc.returncode == 0:
        print('wrote %s' % out)
    else:
        sys.exit('ffmpeg failed (%s)' % proc.returncode)


if __name__ == '__main__':
    main()
