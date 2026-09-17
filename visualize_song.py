#!/usr/bin/env python3
"""Render a video visualisation of a song, showing which keysounds are playing.

The song is a render of the chart (see AGENTS.md 3.5), so at any instant the audio is the
sum of the keysounds whose notes are firing. This draws that as an overlay on the song's
BGA — or on a plain background — and muxes it with the rendered audio.

    python3 visualize_song.py extracted_charts/changa2
    python3 visualize_song.py <song> --mode keysound --no-bga
    python3 visualize_song.py <song> --offset -0.05     # nudge the overlay earlier

Modes
-----
`default`   key mode + difficulty, a lane row that lights as lanes fire, and the keysound
            display.
`keysound`  nothing but the keysound display.

The keysound display lists what is *currently sounding*, each with a lifetime bar showing how
far through its sample it is — so a long sample is visibly still going after its note fired.
Sample lengths are read from the keysound files themselves, so they are the real durations.

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
from parse_chart import parse_ez, parse_ezi, load  # noqa: E402

MONO_CANDIDATES = (
    '/usr/share/fonts/noto/NotoSansMono-Bold.ttf',
    '/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf',
    '/usr/share/fonts/noto/NotoSansMono-Regular.ttf',
    '/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',
)

LANE_TRACK = range(3, 22)          # tracks that can be a playable lane
DEFAULT_ROWS = 12
UNKNOWN_SAMPLE = 0.40              # assumed length when a keysound file is missing

# Panel alphas. Deliberately low so the BGA reads through.
TOP_A, TICKER_A = 110, 130
BAR_FILL, BAR_BG = (235, 245, 255, 235), (255, 255, 255, 55)


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


def resolve_assets_dir(stems, assets_root='extracted_assets'):
    import render_song
    d, score = render_song.resolve_assets(list(stems), root=assets_root)
    return d


def build_events(song_dir, assets_root='extracted_assets'):
    """(chart, events, names, durations).

    events are (start, end, track, keysound, filename, is_long) in time order, where `end` is
    start + the sample's real length, so the display can show how long each one lasts.
    """
    ch = parse_ez(load(os.path.join(song_dir, 'ez.ez'))[0])
    insts = parse_ezi(load(os.path.join(song_dir, 'ezi.ezi'))[0])
    names = {i.index: i.filename for i in insts}

    durations, filemap = {}, {}
    assets = resolve_assets_dir(names.values(), assets_root)
    if assets:
        try:
            import soundfile as sf
            import render_song
            filemap = render_song.build_filemap(assets)
            for idx, fname in names.items():
                path = filemap.get(os.path.splitext(fname)[0].lower())
                if path:
                    try:
                        durations[idx] = sf.info(path).duration
                    except Exception:
                        pass
        except Exception:
            pass

    events = []
    for sec, track, n in ch.note_seconds():
        dur = durations.get(n.keysound, UNKNOWN_SAMPLE)
        events.append((sec, sec + max(0.05, dur), track, n.keysound,
                       names.get(n.keysound, ''), n.is_long))
    events.sort(key=lambda e: e[0])
    return ch, events, names, durations


def find_bga(song_dir, assets_root='extracted_assets'):
    stems = set()
    try:
        insts = parse_ezi(load(os.path.join(song_dir, 'ezi.ezi'))[0])
        stems = {os.path.splitext(i.filename)[0].lower() for i in insts}
    except Exception:
        pass
    best = None
    if os.path.isdir(assets_root):
        for name in sorted(os.listdir(assets_root)):
            d = os.path.join(assets_root, name)
            if not os.path.isdir(d):
                continue
            vids = [f for f in os.listdir(d) if f.lower().endswith(('.mp4', '.webm'))]
            if not vids:
                continue
            have = {os.path.splitext(f)[0].lower() for f in os.listdir(d)}
            score = len(stems & have) / float(max(1, len(stems)))
            if score > 0.9:
                p = os.path.join(d, vids[0])
                if best is None or os.path.getsize(p) > os.path.getsize(best):
                    best = p
    return best


def render_audio(song_dir, out, assets='auto'):
    import render_song
    return render_song.render_one(song_dir, assets, out)


def draw_frame(img, dr, st):
    W, H = st['W'], st['H']
    pad = st['pad']
    t = st['t']

    if st['mode'] == 'default':
        # ---- key mode / difficulty, top left ----------------------------- #
        if st['variant']:
            dr.text((pad, pad - 2), st['variant'], font=st['f_head'],
                    fill=(255, 255, 255, 240),
                    stroke_width=2, stroke_fill=(0, 0, 0, 160))
        if st['lanes']:
            bw = st['lane_w']
            y0 = pad + st['f_head'].size + 10
            for i, track in enumerate(st['lanes']):
                x = pad + i * (bw + 6)
                lit = track in st['active_tracks']
                dr.rectangle([x, y0, x + bw, y0 + st['lane_h']],
                             fill=(120, 230, 160, 220) if lit else (255, 255, 255, 26),
                             outline=(255, 255, 255, 70), width=1)
                if lit:
                    dr.text((x + bw / 2, y0 + st['lane_h'] / 2), str(i + 1),
                            font=st['f_small'], fill=(10, 16, 12, 255), anchor='mm')

    # ---- keysound display ------------------------------------------------ #
    rows = st['rows']                       # currently sounding, newest first
    if not rows:
        return
    row_h = st['f_mono'].size + 10
    panel_h = row_h * st['max_rows'] + 2 * pad
    top = H - panel_h
    dr.rectangle([0, top, W, H], fill=(0, 0, 0, TICKER_A))

    bx, bwid = pad, st['bar_w']
    tx = bx + bwid + 12
    for i, ev in enumerate(rows):
        start, end, track, ks, fname, is_long = ev
        yy = top + pad + i * row_h
        if yy + row_h > H:
            break
        frac = (t - start) / (end - start) if end > start else 1.0
        frac = max(0.0, min(1.0, frac))
        # lifetime bar: an empty track with the elapsed part filled
        by = yy + row_h / 2 - 3
        dr.rectangle([bx, by, bx + bwid, by + 6], fill=BAR_BG)
        dr.rectangle([bx, by, bx + int(bwid * frac), by + 6], fill=BAR_FILL)

        lane = ('%d' % (track - 2)) if track in LANE_TRACK else ('T%d' % track)
        dr.text((tx, yy), lane, font=st['f_mono'], fill=(180, 215, 255, 235))
        dr.text((st['col_ks'], yy), '%d' % ks, font=st['f_mono'], fill=(180, 215, 255, 235))
        col = (250, 210, 120, 240) if is_long else (225, 235, 245, 240)
        dr.text((st['col_name'], yy), fname or '(unknown)', font=st['f_mono'], fill=col)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('song_dir', help='capture directory holding ez.ez and ezi.ezi')
    ap.add_argument('-o', '--out', help='output mp4 (default visualizations/<song>.mp4)')
    ap.add_argument('--mode', choices=('default', 'keysound'), default='default',
                    help='default: mode/difficulty + lanes + keysounds; keysound: keysounds only')
    ap.add_argument('--size', type=parse_size, default=(1280, 720))
    ap.add_argument('--fps', type=int, default=30)
    ap.add_argument('--offset', type=float, default=0.0,
                    help='seconds to shift the overlay by; positive makes it lead the audio '
                         '(use if the overlay looks late)')
    ap.add_argument('--rows', type=int, default=DEFAULT_ROWS,
                    help='keysound rows shown at once (default %d)' % DEFAULT_ROWS)
    ap.add_argument('--bga', help='BGA video to composite onto (default: auto-detect)')
    ap.add_argument('--no-bga', action='store_true', help='plain background only')
    ap.add_argument('--audio', help='rendered audio to mux (default: reuse or render one)')
    ap.add_argument('--assets', default='auto', help="keysound dir for rendering ('auto')")
    ap.add_argument('--render', action='store_true', help='always re-render the audio')
    ap.add_argument('--crf', type=int, default=20, help='x264 quality (lower is better)')
    ap.add_argument('--preset', default='veryfast')
    ap.add_argument('--until', type=float, help='stop at this many seconds (for testing)')
    ap.add_argument('--start', type=float, default=0.0,
                    help='start the clip at this many seconds (for quick checks)')
    args = ap.parse_args()

    W, H = args.size
    song = os.path.basename(os.path.normpath(args.song_dir))
    out = args.out or os.path.join('visualizations', '%s.mp4' % song)
    if os.path.dirname(out):
        os.makedirs(os.path.dirname(out), exist_ok=True)

    ch, events, names, durations = build_events(args.song_dir)
    if not events:
        sys.exit('%s has no notes' % args.song_dir)
    duration = max(ch.duration, max(e[0] for e in events) + 0.5)
    if args.until:
        duration = min(duration, args.until)
    start = max(0.0, args.start)
    duration = max(0.5, duration - start)

    label = chart_label(args.song_dir)
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
    try:
        import soundfile as sf
        adur = sf.info(audio).duration
        if adur and adur > 1.0:
            duration = min(duration, max(0.5, adur - start))
    except Exception:
        pass

    # ---- background ------------------------------------------------------- #
    bga = None if args.no_bga else (args.bga or find_bga(args.song_dir))
    n_frames = int(duration * args.fps) + 1

    # The background is forced to the output frame rate so the overlay maps 1:1 with it —
    # mixing 60 fps BGA with a 30 fps overlay lets the compositor resample, which is a
    # plausible source of the overlay landing a frame or two late.
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
            '[1:v]fps=%d,scale=%d:%d:force_original_aspect_ratio=increase,crop=%d:%d,setsar=1[bg];'
            '[bg][0:v]overlay=0:0:format=auto,format=yuv420p[v]' % (args.fps, W, H, W, H),
            '-map', '[v]', '-map', '2:a', '-r', str(args.fps),
            '-c:v', 'libx264', '-preset', args.preset, '-crf', str(args.crf),
            '-c:a', 'aac', '-b:a', '192k', '-t', '%.3f' % duration, out]
    if start:
        # seek the audio and the BGA to the clip start (insert before their -i)
        ai = cmd.index(audio)
        cmd[ai - 1:ai - 1] = ['-ss', '%.3f' % start]
        if bga:
            bi = cmd.index(bga)
            cmd[bi - 1:bi - 1] = ['-ss', '%.3f' % start]

    f_head, f_small, f_mono = font(max(18, H // 34)), font(max(12, H // 60)), font(max(11, H // 58))
    col_ks = 18 + 110 + 12 + 54
    col_name = col_ks + 74
    lanes = sorted({t for _s, _e, t, _k, _f, _l in events if t in LANE_TRACK})
    lane_w = max(24, min(34, (W - 2 * 18 - 6 * max(1, len(lanes))) // max(1, len(lanes))))
    st = dict(W=W, H=H, mode=args.mode, variant=variant, lanes=lanes,
              f_head=f_head, f_small=f_small, f_mono=f_mono,
              pad=18, lane_w=lane_w, lane_h=max(18, f_small.size + 10),
              bar_w=110, col_ks=col_ks, col_name=col_name,
              max_rows=args.rows, rows=[], active_tracks=set(), t=0.0)

    # Guard: `-y` lets ffmpeg overwrite its output, and the output must be the last argument.
    # A malformed command build once made an input path the output, and ffmpeg truncated a
    # 49 MB BGA to zero bytes.
    inputs = {audio} | ({bga} if bga else set())
    if out in inputs:
        sys.exit('refusing to run: output %s is also an input' % out)
    if cmd[-1] != out:
        sys.exit('refusing to run: %s is not the last ffmpeg argument' % out)

    print('rendering %d frames at %dx%d @ %d fps (%.1fs), mode=%s -> %s'
          % (n_frames, W, H, args.fps, duration, args.mode, out))
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    img = Image.new('RGBA', (W, H), (0, 0, 0, 0))
    dr = ImageDraw.Draw(img, 'RGBA')
    next_i, live = 0, []
    empty = Image.new('RGBA', (W, H), (0, 0, 0, 0))
    try:
        for fi in range(n_frames):
            # --offset shifts the overlay's notion of time, so a positive value makes it lead
            # the audio (use it if the overlay looks late). The audio itself is untouched.
            vt = start + fi / float(args.fps) + args.offset
            while next_i < len(events) and events[next_i][0] <= vt:
                live.append(events[next_i])
                next_i += 1
            live = [e for e in live if e[1] > vt]      # drop ones that finished sounding
            st['rows'] = sorted(live, key=lambda e: -e[0])[:args.rows]
            st['active_tracks'] = {e[2] for e in live}
            st['t'] = vt
            img.paste(empty, (0, 0))
            draw_frame(img, dr, st)
            proc.stdin.write(img.tobytes())
            if fi % (args.fps * 10) == 0:
                print('  %5.1f%%' % (100.0 * fi / n_frames), flush=True)
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
        print('ffmpeg command was:\n  %s' % ' '.join(cmd))
        sys.exit('ffmpeg failed (%s)' % proc.returncode)


if __name__ == '__main__':
    main()
