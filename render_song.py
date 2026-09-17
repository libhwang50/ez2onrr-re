#!/usr/bin/env python3
"""Render an EZ2ON REBOOT: R song by playing its chart.

The song is not stored anywhere — it is a render of the chart. Every type-1 note, on
every track, triggers its keysound at its scheduled time; the player's lanes (tracks 3-6)
and the auto-played layers (23-63) are equally part of it, and the `MR` keysound on
track 22 is a supplementary layer for instruments too long or too incidental to sample,
not the song itself. See AGENTS.md 3.5 / 3.6.

Usage
-----
    python3 render_song.py <song_dir> --assets extracted_assets/<song_id> -o out.wav

`song_dir` must hold a decrypted `ez.ez` and `ezi.ezi` (what `dump_song.py` writes, or
`decrypt_chart.py --out` produces). Keysounds are matched to the `.ezi` filenames by stem,
so `00-MR.wav` in the index resolves to `00-MR.flac` on disk.

Requires numpy and soundfile (both editable via `uv pip install --python .venv/bin/python
numpy soundfile`).

Limitations
-----------
* A long note plays its keysound once, as a normal note. If a hold is meant to sustain the
  sample, that is not reproduced — the `flags` value carries the length but its unit is
  unknown (AGENTS.md 3.5).
* `velocity` is 127 for essentially every note, so it is applied as a gain but is untested.
"""
import argparse
import os
import sys

import numpy as np
import soundfile as sf

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse_chart import parse_ezi, load  # noqa: E402


def resample(x, sr_in, sr_out):
    """Linear-interpolation resample of a (frames, channels) float32 array."""
    if sr_in == sr_out or x.shape[0] == 0:
        return x
    n_out = max(1, int(round(x.shape[0] * sr_out / sr_in)))
    idx = np.linspace(0.0, x.shape[0] - 1, n_out)
    i0 = np.floor(idx).astype(np.int64)
    i1 = np.minimum(i0 + 1, x.shape[0] - 1)
    frac = (idx - i0).astype(np.float32)[:, None]
    return (x[i0] * (1.0 - frac) + x[i1] * frac).astype(np.float32)


def build_index(ezi):
    """keysound index -> filename stem, lowercased."""
    return {i.index: os.path.splitext(i.filename)[0] for i in ezi}


def build_filemap(asset_dir):
    """stem (lowercased) -> path, for every audio file in the asset dir."""
    out = {}
    for fn in os.listdir(asset_dir):
        stem, ext = os.path.splitext(fn)
        if ext.lower() in ('.flac', '.ogg', '.wav', '.mp3'):
            out[stem.lower()] = os.path.join(asset_dir, fn)
    return out


def resolve_assets(ezi_stems, root='extracted_assets', min_score=0.9):
    """Find the extracted_assets/<song_id> whose files match this chart's keysounds.

    `dump_song.py` names its directories song_<hash> and does not record the song id, so
    match on the keysound stems the `.ezi` declares instead.
    """
    want = {s.lower() for s in ezi_stems}
    best = (0.0, None)
    if not os.path.isdir(root):
        return None, 0.0
    for name in sorted(os.listdir(root)):
        d = os.path.join(root, name)
        if not os.path.isdir(d):
            continue
        have = {os.path.splitext(f)[0].lower() for f in os.listdir(d)}
        if not have:
            continue
        score = len(want & have) / float(max(1, len(want)))
        if score > best[0]:
            best = (score, d)
    return (best[1], best[0]) if best[0] >= min_score else (None, best[0])


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('song_dir', help='directory holding ez.ez and ezi.ezi')
    ap.add_argument('--assets', required=True,
                    help="extracted keysounds for this song, or 'auto' to match by contents")
    ap.add_argument('-o', '--out', help='output audio file (default <song_dir>.flac)')
    ap.add_argument('--rate', type=int, default=44100, help='output sample rate (default 44100)')
    ap.add_argument('--gain', type=float, default=1.0, help='master gain before normalisation')
    ap.add_argument('--no-normalize', action='store_true', help='skip peak normalisation')
    ap.add_argument('--tracks', help='only these track indices, e.g. 3,4,5,6')
    args = ap.parse_args()

    ez = os.path.join(args.song_dir, 'ez.ez')
    ezi = os.path.join(args.song_dir, 'ezi.ezi')
    if not (os.path.exists(ez) and os.path.exists(ezi)):
        sys.exit('need both ez.ez and ezi.ezi in %s' % args.song_dir)

    data, was_enc = load(ez)
    from parse_chart import parse_ez
    ch = parse_ez(data)
    ezi_data, _ = load(ezi)
    ezi_index = parse_ezi(ezi_data)
    idx2stem = build_index(ezi_index)
    if args.assets == 'auto':
        assets, score = resolve_assets(list(idx2stem.values()))
        if not assets:
            sys.exit('no extracted_assets/* matches this chart (best overlap %.2f)' % score)
        print('  matched assets %s (%.1f%% of keysounds)' % (assets, score * 100))
        args.assets = assets
    filemap = build_filemap(args.assets)

    only = None
    if args.tracks:
        only = {int(x) for x in args.tracks.split(',') if x.strip() != ''}

    seconds = ch.duration
    rate = args.rate
    # Leave room for the last notes' sample tails, then trim trailing silence, so a note
    # landing exactly on the final tick is not dropped.
    n_frames = int(np.ceil(seconds * rate)) + 30 * rate
    mix = np.zeros((n_frames, 2), dtype=np.float32)

    # decode each needed keysound once
    cache, missing_name, missing_file, used = {}, 0, 0, 0
    events = []
    for sec, track, note in ch.note_seconds():
        if only is not None and track not in only:
            continue
        stem = idx2stem.get(note.keysound)
        if stem is None:
            missing_name += 1
            continue
        path = filemap.get(stem.lower())
        if path is None:
            missing_file += 1
            continue
        events.append((sec, stem, path, note.velocity))
    if missing_name:
        print('  !! %d notes reference a keysound absent from the .ezi' % missing_name)
    if missing_file:
        print('  !! %d keysounds are not present in %s' % (missing_file, args.assets))

    for sec, stem, path, vel in events:
        if stem not in cache:
            x, sr = sf.read(path, dtype='float32', always_2d=True)
            x = resample(x, sr, rate)
            if x.shape[1] == 1:
                x = np.repeat(x, 2, axis=1)
            elif x.shape[1] > 2:
                x = x[:, :2]
            cache[stem] = x
        buf = cache[stem]
        off = int(round(sec * rate))
        if off >= n_frames:
            continue
        n = min(buf.shape[0], n_frames - off)
        mix[off:off + n] += buf[:n] * (vel / 127.0)
        used += 1

    peak = float(np.max(np.abs(mix))) if mix.size else 0.0
    if not args.no_normalize and peak > 0:
        mix *= (0.99 / peak)
    mix *= args.gain
    np.clip(mix, -1.0, 1.0, out=mix)

    # trim trailing silence so the file ends where the song does
    env = np.abs(mix).max(axis=1)
    last = int(np.argmax(env[::-1] > 1e-6)) if env.size else 0
    if last:
        mix = mix[:len(mix) - last + 1]

    out = args.out or (os.path.basename(os.path.normpath(args.song_dir)) + '.flac')
    sf.write(out, mix, rate, format='FLAC')
    print('  rendered %d events from %d distinct keysounds -> %s' % (used, len(cache), out))
    print('  chart %.2f s, output %.2f s @ %d Hz, peak before normalise %.3f'
          % (seconds, len(mix) / rate, rate, peak))


if __name__ == '__main__':
    main()
