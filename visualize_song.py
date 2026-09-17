#!/usr/bin/env python3
"""Render a video visualisation of a song, showing which keysounds are playing.

The song is a render of the chart (see AGENTS.md 3.5), so at any instant the audio is the
sum of the keysounds whose notes are firing. This draws that as an overlay on the song's
BGA — or on a plain background — and muxes it with the rendered audio.

    python3 visualize_song.py extracted_charts/changa2
    python3 visualize_song.py <song> --mode keysound --no-bga
    python3 visualize_song.py <song> --offset 0.03          # nudge the overlay later

Modes
-----
`default`   key mode + difficulty, a lane row that lights as lanes fire, and the keysound
            display.
`keysound`  nothing but the keysound display.

Overlay
-------
No panel backgrounds — everything is outlined text and thin bars so the BGA reads through.
The keysound display lists what is *currently sounding*, each in a fixed slot with a lifetime
bar showing how far through its sample it is. A playing keysound keeps its row until it
finishes and new ones fill the gaps, so nothing shifts around under the reader. Sample
lengths come from the keysound files themselves.

If a BGA is used, the overlay adopts its resolution and frame rate (1280x720 at 60 fps for
Changa 2) so the BGA is passed through untouched; --size and --fps override that.

Requires Pillow and ffmpeg.
"""

import argparse
import bisect
import json
import os
import re
import shlex
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse_chart import parse_ez, parse_ezi, load  # noqa: E402

MONO_CANDIDATES = (
    "/usr/share/fonts/noto/NotoSansMono-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
    "/usr/share/fonts/noto/NotoSansMono-Regular.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
)

LANE_TRACK = range(3, 22)  # tracks that can be a playable lane
UNKNOWN_SAMPLE = 0.40  # assumed length when a keysound file is missing

SHADOW = (0, 0, 0, 180)  # outline colour behind every label
MAX_COLS = 4  # keysound display columns, used when one column cannot fit the chart


def font(size):
    for p in MONO_CANDIDATES:
        if os.path.exists(p):
            try:
                return ImageFont.truetype(p, size)
            except Exception:
                pass
    return ImageFont.load_default()


def parse_size(s):
    m = re.match(r"^(\d+)x(\d+)$", s)
    if not m:
        raise argparse.ArgumentTypeError("expected WxH, e.g. 1280x720")
    return int(m.group(1)), int(m.group(2))


def probe_video(path):
    """(width, height, fps_float, fps_arg) for a video, or None."""
    try:
        out = (
            subprocess.check_output(
                [
                    "ffprobe",
                    "-v",
                    "quiet",
                    "-select_streams",
                    "v:0",
                    "-show_entries",
                    "stream=width,height,r_frame_rate",
                    "-of",
                    "csv=p=0",
                    path,
                ],
                stderr=subprocess.DEVNULL,
            )
            .decode()
            .strip()
            .splitlines()[0]
        )
        w, h, rate = out.split(",")
        num, den = (rate.split("/") + ["1"])[:2]
        num, den = int(num), int(den) or 1
        return int(w), int(h), num / float(den), "%d/%d" % (num, den)
    except Exception:
        return None


def chart_label(song_dir):
    try:
        return (json.load(open(os.path.join(song_dir, "ident.json"))) or {}).get(
            "label"
        ) or {}
    except (OSError, ValueError):
        return {}


def build_events(song_dir, assets_root="extracted_assets"):
    """(chart, events, names, durations); events are (start, end, track, ks, filename, long)."""
    ch = parse_ez(load(os.path.join(song_dir, "ez.ez"))[0])
    insts = parse_ezi(load(os.path.join(song_dir, "ezi.ezi"))[0])
    names = {i.index: i.filename for i in insts}

    durations = {}
    try:
        import soundfile as sf
        import render_song

        filemap = {}
        assets, score = render_song.resolve_assets(names.values(), root=assets_root)
        if assets:
            filemap = render_song.build_filemap(assets)
            for idx, fname in names.items():
                path = filemap.get(os.path.splitext(fname)[0].lower())
                if path:
                    try:
                        durations[idx] = sf.info(path).duration
                    except Exception:
                        pass
        if not durations:
            print(
                "warning: no keysound durations resolved (best asset match %.2f%%); "
                "lifetime bars will use a %.2fs placeholder"
                % (100.0 * score, UNKNOWN_SAMPLE),
                flush=True,
            )
    except Exception as e:
        print("warning: could not read keysound durations: %s" % e, flush=True)

    events = [
        (
            sec,
            sec + max(0.05, durations.get(n.keysound, UNKNOWN_SAMPLE)),
            track,
            n.keysound,
            names.get(n.keysound, ""),
            n.is_long,
        )
        for sec, track, n in ch.note_seconds()
    ]
    events.sort(key=lambda e: e[0])
    return ch, events, names, durations


def max_simultaneous(events, times=None):
    """Peak number of keysounds sounding at once.

    With `times`, only those instants are sampled — normally the frames actually rendered. That
    matters because a spike can be narrower than a frame: Rebind's true peak is 37 keysounds
    for about 30 ms, which at 24 fps no frame ever shows, so sizing slots to it would add a
    column that is always empty. Without `times`, the true peak over the timeline.
    """
    starts = sorted(e[0] for e in events)
    ends = sorted(e[1] for e in events)

    def at(t):
        return bisect.bisect_right(starts, t) - bisect.bisect_right(ends, t)

    if times is None:
        return max((at(t) for t in sorted(set(starts) | set(ends))), default=0)
    return max((at(t) for t in times), default=0)


def find_bga(song_dir, assets_root="extracted_assets"):
    stems = set()
    try:
        insts = parse_ezi(load(os.path.join(song_dir, "ezi.ezi"))[0])
        stems = {os.path.splitext(i.filename)[0].lower() for i in insts}
    except Exception:
        pass
    best = None
    if os.path.isdir(assets_root):
        for name in sorted(os.listdir(assets_root)):
            d = os.path.join(assets_root, name)
            if not os.path.isdir(d):
                continue
            vids = [f for f in os.listdir(d) if f.lower().endswith((".mp4", ".webm"))]
            if not vids:
                continue
            have = {os.path.splitext(f)[0].lower() for f in os.listdir(d)}
            if len(stems & have) / float(max(1, len(stems))) > 0.9:
                p = os.path.join(d, vids[0])
                if best is None or os.path.getsize(p) > os.path.getsize(best):
                    best = p
    return best


def render_audio(song_dir, out, assets="auto"):
    import render_song

    return render_song.render_one(song_dir, assets, out)


def txt(dr, xy, s, fnt, fill, st, anchor=None):
    dr.text(
        xy, s, font=fnt, fill=fill, anchor=anchor,
        stroke_width=st['stroke'], stroke_fill=SHADOW
    )


def draw_frame(img, dr, st):
    W, H = st["W"], st["H"]
    pad = st["pad"]
    t = st["t"]

    if st["mode"] == "default":
        if st["variant"]:
            txt(dr, (pad, pad - 2), st["variant"], st["f_head"], (255, 255, 255, 245), st)
        bw, bh = st["lane_w"], st["lane_h"]
        y0 = pad + st["f_head"].size + 12
        for i, track in enumerate(st["lanes"]):
            x = pad + i * (bw + 6)
            lit = track in st["active_tracks"]
            dr.rectangle(
                [x, y0, x + bw, y0 + bh],
                fill=(120, 230, 160, 210) if lit else (0, 0, 0, 70),
                outline=(255, 255, 255, 130),
                width=2,
            )
            if lit:
                txt(
                    dr,
                    (x + bw / 2, y0 + bh / 2),
                    str(i + 1),
                    st["f_small"],
                    (8, 14, 10, 255),
                    st,
                    anchor="mm",
                )

    # ---- keysound display: fixed slots, no panel, outlined labels ---------- #
    row_h = st["row_h"]
    for i, ev in enumerate(st["slots"]):
        if ev is None:
            continue
        start, end, track, ks, fname, is_long = ev
        # column-major: newer keysounds fill the first column before spilling right
        c, r = divmod(i, st["rows_per_col"])
        x0 = st["pad"] + c * st["colw"]
        yy = st["top"] + r * row_h
        frac = 1.0 if end <= start else (t - start) / (end - start)
        frac = max(0.0, min(1.0, frac))

        bx, bwid = x0, st["bar_w"]
        by = yy + row_h / 2 - 3
        dr.rectangle([bx, by, bx + bwid, by + 6], outline=(255, 255, 255, 120), width=1)
        if frac > 0:
            dr.rectangle(
                [bx + 1, by + 1, bx + 1 + int((bwid - 2) * frac), by + 5],
                fill=(235, 245, 255, 235),
            )

        lane = ("%d" % (track - 2)) if track in LANE_TRACK else ("T%d" % track)
        txt(dr, (x0 + st["off_lane"], yy), lane, st["f_mono"], (190, 220, 255, 245), st)
        txt(dr, (x0 + st["off_ks"], yy), "%d" % ks, st["f_mono"], (190, 220, 255, 245), st)
        name = fname or "(unknown)"
        if len(name) > st["name_chars"]:
            name = name[: max(1, st["name_chars"] - 2)] + ".."
        txt(
            dr,
            (x0 + st["off_name"], yy),
            name,
            st["f_mono"],
            (250, 215, 130, 250) if is_long else (232, 238, 248, 250),
            st,
        )


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("song_dir", help="capture directory holding ez.ez and ezi.ezi")
    ap.add_argument(
        "-o", "--out", help="output mp4 (default visualizations/<song>.mp4)"
    )
    ap.add_argument(
        "--mode",
        choices=("default", "keysound"),
        default="default",
        help="default: mode/difficulty + lanes + keysounds; keysound: keysounds only",
    )
    ap.add_argument(
        "--size", type=parse_size, help="output WxH (default: the BGA's, else 1280x720)"
    )
    ap.add_argument(
        "--fps", type=float, help="output frame rate (default: the BGA's, else 30)"
    )
    ap.add_argument(
        "--offset",
        type=float,
        default=0.0,
        help="seconds to shift the overlay by; positive makes it lead the audio "
        "(use if the overlay looks late)",
    )
    ap.add_argument(
        "--rows",
        default="auto",
        help="keysound slots: an integer, or 'auto' (default) to size them to the chart's "
        "peak simultaneous keysounds, capped so the display fits the frame",
    )
    ap.add_argument("--bga", help="BGA video to composite onto (default: auto-detect)")
    ap.add_argument("--no-bga", action="store_true", help="plain background only")
    ap.add_argument(
        "--audio", help="rendered audio to mux (default: reuse or render one)"
    )
    ap.add_argument(
        "--assets", default="auto", help="keysound dir for rendering ('auto')"
    )
    ap.add_argument("--render", action="store_true", help="always re-render the audio")
    ap.add_argument(
        "--crf",
        type=int,
        default=18,
        help="x264 quality (lower is better; default 18, near-transparent for the BGA)",
    )
    ap.add_argument(
        "--outline",
        type=int,
        default=None,
        help="label outline width in px (default scales with the frame: 1 at 720p)",
    )
    ap.add_argument("--preset", default="veryfast")
    ap.add_argument(
        "--ffmpeg-args",
        metavar="ARGS",
        help="extra OUTPUT options for ffmpeg, e.g. "
             "--ffmpeg-args='-tune animation -movflags +faststart -profile:v high'. Quote the "
             "whole string (shell-split). Use = when the value starts with '-', or argparse "
             "reads it as an option.",
    )
    ap.add_argument(
        "--ffmpeg-global-args",
        metavar="ARGS",
        help="extra GLOBAL/input options for ffmpeg, placed before the first input, e.g. "
             "--ffmpeg-global-args='-hide_banner -filter_threads 2'",
    )
    ap.add_argument(
        "--until", type=float, help="stop at this many seconds (for testing)"
    )
    ap.add_argument(
        "--start",
        type=float,
        default=0.0,
        help="start the clip at this many seconds (for quick checks)",
    )
    args = ap.parse_args()

    # a capture is nested as <song>/<keymode>/<difficulty>, so the basename alone would be
    # just "shd" — keep the path components in the output name
    import render_song
    song = render_song.chart_name(args.song_dir)
    out = args.out or os.path.join("visualizations", "%s.mp4" % song)
    # `-o somedir/` is a natural thing to type; ffmpeg needs a file, so append the default
    if out.endswith(os.sep) or os.path.isdir(out):
        out = os.path.join(out, "%s.mp4" % song)
    if os.path.dirname(out):
        os.makedirs(os.path.dirname(out), exist_ok=True)

    ch, events, names, durations = build_events(args.song_dir)
    if not events:
        sys.exit("%s has no notes" % args.song_dir)

    # ---- background, and the format we follow it in ----------------------- #
    if args.no_bga:
        bga = None
    elif args.bga:
        if not os.path.exists(args.bga):
            sys.exit("--bga file not found: %s" % args.bga)
        bga = args.bga
    else:
        bga = find_bga(args.song_dir)
        if not bga:
            # Say so loudly: this used to fall through to a plain background silently, and a
            # black frame is easy to mistake for a dark BGA.
            hint = (chart_label(args.song_dir).get("song") or "").lower()
            print("!! no extracted BGA found for this chart - the background will be blank.")
            print("   extract it, then re-run:")
            print("       python3 extract_assets.py %s --bga"
                  % (hint or "<song_id>"))
            print("   (--no-bga silences this, --bga FILE points at one directly)")
            if os.path.isdir("extracted_assets") and hint:
                have = [d for d in os.listdir("extracted_assets")
                        if os.path.isdir(os.path.join("extracted_assets", d))]
                near = [d for d in have if hint and (hint in d or d in hint)]
                if near:
                    print("   extracted asset dirs that look related: %s" % ", ".join(sorted(near)))
    native = probe_video(bga) if bga else None
    if native:
        W, H, fps_f, fps_arg = native
        if args.size:
            W, H = args.size
        if args.fps:
            fps_f = args.fps
            fps_arg = "%.6f" % args.fps
        print("background: %s  (%dx%d @ %s fps)" % (bga, W, H, fps_arg))
    else:
        W, H = args.size or (1280, 720)
        fps_f = args.fps or 30.0
        fps_arg = "%.6f" % fps_f

    duration = max(ch.duration, max(e[0] for e in events) + 0.5)
    if args.until:
        duration = min(duration, args.until)
    start = max(0.0, args.start)
    duration = max(0.5, duration - start)

    label = chart_label(args.song_dir)
    variant = " ".join(x for x in (label.get("keymode"), label.get("difficulty")) if x)

    # ---- audio ------------------------------------------------------------ #
    audio = args.audio
    if args.render or not audio:
        default = os.path.join("rendered_songs", song + ".flac")
        if not args.render and os.path.exists(default):
            audio = default
        else:
            audio = "/tmp/_viz_%s.flac" % song
            print("rendering audio -> %s" % audio)
            render_audio(args.song_dir, audio, args.assets)
    try:
        import soundfile as sf

        adur = sf.info(audio).duration
        if adur and adur > 1.0:
            duration = min(duration, max(0.5, adur - start))
    except Exception:
        pass

    n_frames = int(duration * fps_f) + 1
    cmd = [
        "ffmpeg",
        "-y",
        "-loglevel",
        "error",
        "-f",
        "rawvideo",
        "-pix_fmt",
        "rgba",
        "-s",
        "%dx%d" % (W, H),
        "-r",
        fps_arg,
        "-i",
        "-",
    ]
    if bga:
        cmd += ["-i", bga]
    else:
        cmd += [
            "-f",
            "lavfi",
            "-i",
            "color=c=0x0b0d12:s=%dx%d:r=%s:d=%.3f" % (W, H, fps_arg, duration),
        ]
    cmd += ["-i", audio]
    # Keep the BGA's own rate so the overlay maps 1:1. Only touch its pixels if the caller
    # asked for a different size — otherwise it is passed through unscaled and uncropped.
    if bga and native and (W, H) != (native[0], native[1]):
        pre = (
            "[1:v]fps=%s,scale=%d:%d:force_original_aspect_ratio=increase,crop=%d:%d,"
            "setsar=1[bg]" % (fps_arg, W, H, W, H)
        )
    else:
        pre = "[1:v]fps=%s[bg]" % fps_arg
    cmd += [
        "-filter_complex",
        "%s;[bg][0:v]overlay=0:0:format=auto,format=yuv420p[v]" % pre,
        "-map",
        "[v]",
        "-map",
        "2:a",
        "-r",
        fps_arg,
        "-c:v",
        "libx264",
        "-preset",
        args.preset,
        "-crf",
        str(args.crf),
        "-c:a",
        "aac",
        "-b:a",
        "192k",
        "-t",
        "%.3f" % duration,
        out,
    ]
    if start:
        ai = cmd.index(audio)
        cmd[ai - 1 : ai - 1] = ["-ss", "%.3f" % start]
        if bga:
            bi = cmd.index(bga)
            cmd[bi - 1 : bi - 1] = ["-ss", "%.3f" % start]

    # Extra ffmpeg options, split with shell rules so quoting works as typed. Output options go
    # just before the output path; global ones go before the first input, where ffmpeg requires
    # them. Inserting rather than replacing keeps the output last, which the guard below checks.
    if args.ffmpeg_global_args:
        cmd[4:4] = shlex.split(args.ffmpeg_global_args)
    if args.ffmpeg_args:
        cmd[-1:-1] = shlex.split(args.ffmpeg_args)
    if args.ffmpeg_args or args.ffmpeg_global_args:
        print("ffmpeg command:\n  %s" % " ".join(shlex.quote(a) for a in cmd))

    # Guard: `-y` lets ffmpeg overwrite its output, and the output must be last. A malformed
    # build once made an input path the output, truncating a 49 MB BGA to zero bytes.
    inputs = {audio} | ({bga} if bga else set())
    if out in inputs:
        sys.exit("refusing to run: output %s is also an input" % out)
    if cmd[-1] != out:
        sys.exit("refusing to run: %s is not the last ffmpeg argument" % out)

    f_head = font(max(18, H // 34))
    f_small = font(max(12, H // 60))
    f_mono = font(max(11, H // 58))
    row_h = f_mono.size + 11
    pad = max(14, H // 40)
    lanes = sorted({e[2] for e in events if e[2] in LANE_TRACK})
    lane_w = max(
        22,
        min(
            int(H * 0.048), (W - 2 * pad - 6 * max(1, len(lanes))) // max(1, len(lanes))
        ),
    )
    # ---- keysound slots: size to the chart, in columns if one will not fit ----- #
    frame_times = [start + i / fps_f for i in range(n_frames)]
    peak_on_frames = max_simultaneous(events, times=frame_times)
    peak_true = max_simultaneous(events)
    if peak_on_frames < peak_true:
        print("note: true peak is %d keysound(s) but only %d coincide on a rendered frame at "
              "%.4g fps; sizing to %d." % (peak_true, peak_on_frames, fps_f, peak_on_frames))
    peak = peak_on_frames
    fit = max(1, int(H * 0.60 / row_h))              # rows that fit in a single column
    if str(args.rows).lower() == "auto":
        wanted = peak
    else:
        try:
            wanted = max(1, int(args.rows))
        except (TypeError, ValueError):
            sys.exit("--rows must be an integer or 'auto'")
    # Rather than dropping keysounds when they exceed the height, spill into more columns.
    cols = max(1, min(MAX_COLS, (wanted + fit - 1) // fit))
    rows_per_col = max(1, (wanted + cols - 1) // cols)
    total = cols * rows_per_col
    if total < wanted:
        print("note: %d slots wanted but only %d fit in %d column(s); raise --size for more."
              % (wanted, total, cols))
    if total < peak:
        print("note: %d keysounds sound at once at peak but %d slot(s) are shown, so some are "
              "evicted." % (peak, total))
    print("peak simultaneous keysounds: %d -> %d row(s) x %d column(s) = %d slots"
          % (peak, rows_per_col, cols, total))

    colw = W / float(cols)
    bar_w = max(40, int(min(W * 0.085, colw * 0.14)))
    off_lane = bar_w + max(8, int(f_mono.size * 0.7))
    off_ks = off_lane + max(28, int(f_mono.size * 2.9))
    off_name = off_ks + max(44, int(f_mono.size * 4.4))
    # keep names inside their column instead of running into the next one
    char_w = max(1.0, f_mono.getlength("M") or 1.0)
    name_chars = max(8, int((colw - pad - off_name - 4) / char_w))
    stroke = args.outline if args.outline is not None else max(1, int(round(H / 720.0)))
    st = dict(
        W=W,
        H=H,
        mode=args.mode,
        variant=variant,
        lanes=lanes,
        f_head=f_head,
        f_small=f_small,
        f_mono=f_mono,
        stroke=stroke,
        pad=pad,
        lane_w=lane_w,
        lane_h=max(16, f_small.size + 8),
        colw=colw,
        rows_per_col=rows_per_col,
        bar_w=bar_w,
        off_lane=off_lane,
        off_ks=off_ks,
        off_name=off_name,
        name_chars=name_chars,
        row_h=row_h,
        top=H - pad - rows_per_col * row_h,
        slots=[None] * total,
        active_tracks=set(),
        t=0.0,
    )

    print(
        "rendering %d frames at %dx%d @ %s fps (%.1fs), mode=%s -> %s"
        % (n_frames, W, H, fps_arg, duration, args.mode, out)
    )
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    dr = ImageDraw.Draw(img, "RGBA")
    empty = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    next_i = 0
    dropped = 0
    try:
        for fi in range(n_frames):
            vt = start + fi / fps_f + args.offset
            # slots keep a playing keysound in place until its sample ends
            for i, s in enumerate(st["slots"]):
                if s is not None and s[1] <= vt:
                    st["slots"][i] = None
            while next_i < len(events) and events[next_i][0] <= vt:
                ev = events[next_i]
                next_i += 1
                if ev[1] <= vt:
                    continue
                free = next((i for i, s in enumerate(st["slots"]) if s is None), None)
                if free is None:
                    # evict whichever has least left to run
                    free = min(range(len(st["slots"])), key=lambda i: st["slots"][i][1])
                    dropped += 1
                st["slots"][free] = ev
            st["active_tracks"] = {s[2] for s in st["slots"] if s}
            st["t"] = vt
            img.paste(empty, (0, 0))
            draw_frame(img, dr, st)
            proc.stdin.write(img.tobytes())
            if fi % int(max(1, fps_f * 10)) == 0:
                print("  %5.1f%%" % (100.0 * fi / n_frames), flush=True)
    except BrokenPipeError:
        pass
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait()
    if dropped:
        print(
            "note: %d keysound(s) evicted for lack of a free slot (raise --rows)"
            % dropped
        )
    if proc.returncode == 0:
        print("wrote %s" % out)
    else:
        print("ffmpeg command was:\n  %s" % " ".join(cmd))
        sys.exit("ffmpeg failed (%s)" % proc.returncode)


if __name__ == "__main__":
    main()
