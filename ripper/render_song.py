#!/usr/bin/env python3
"""Render an EZ2ON REBOOT: R song by playing its chart.

The song is not stored anywhere — it is a render of the chart. Every type-1 note, on
every track, triggers its keysound at its scheduled time; the player's lanes (tracks 3-6)
and the auto-played layers (23-63) are equally part of it, and the `MR` keysound on
track 22 is a supplementary layer for instruments too long or too incidental to sample,
not the song itself. See §3.5 / 3.6.

Usage
-----
    python3 ripper/render_song.py <song_dir> --assets auto -o out.flac
    python3 ripper/render_song.py --all -o rendered_songs/

Output names come from the capture's `ident.json`: the song's title when the metadata table
resolved one (`Hyper_Magic_4K_SHD.flac`), else its resource codename, plus the key mode and
difficulty so variants do not collide. An unidentified capture keeps its `song_<hash>` name.
Without `-o`, a render is written to `rendered_songs/<name>.flac`.

`song_dir` must hold a decrypted `ez.ez` and `ezi.ezi` (what `ripper/dump_song.py` writes, or
`ripper/decrypt_chart.py --out` produces); a parent directory is accepted when it contains
exactly one chart. `--assets auto` finds the matching
`extracted_assets/<song_id>` by comparing keysound filenames, which is necessary because
`ripper/dump_song.py` names its directories `song_<hash>` and never records the song id.

Requires numpy and soundfile (`uv pip install --python .venv/bin/python numpy soundfile`).

Verified
--------
A/B'd by ear against in-game gameplay and reported as an exact match. **Long notes behave
exactly like normal notes: the keysound plays once and is not sustained.** The `flags`
field still marks which notes are long, but it has no effect on audio, so nothing extra is
needed here — the distinction must matter to judgement or visuals.

Known imprecision: `velocity` is 127 for essentially every note, so it is applied as a gain
but never exercised.
"""
import argparse
import os
import re
import sys

import numpy as np
import soundfile as sf

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse_chart import parse_ez, parse_ezi, load  # noqa: E402
import song_meta  # noqa: E402
from ez2lib import chart_label  # noqa: E402

AUDIO_EXT = ('.flac', '.ogg', '.wav', '.mp3')


def tag_file(path, song, label=None):
    """Write Vorbis comments onto a rendered FLAC. Returns the tags written.

    The song's title and composer come from the game's `MUSIC_NAME_DIC` (see
    `ripper/harvest_metadata.py`); the mode/difficulty come from the capture's label. Nothing is
    written when the song cannot be resolved, so a render never gets wrong credits.
    """
    label = label or {}
    tags = song_meta.tags(song) if song else {}
    if not tags:
        return {}
    bits = ' '.join(b for b in (label.get('keymode'), label.get('difficulty')) if b)
    extra = []
    if bits:
        extra.append(bits)
    if label.get('gamemode'):
        extra.append('gamemode %s' % label['gamemode'])
    if extra:
        tags['comment'] = (tags.get('comment', '') +
                           ('; ' if tags.get('comment') else '') + '; '.join(extra))
    tags['albumartist'] = tags.get('artist', '')
    try:
        from mutagen.flac import FLAC
        f = FLAC(path)
        f.delete()
        for k, v in tags.items():
            if v:
                f[k] = [str(v)]
        f.save()
    except ImportError:
        return {}
    return tags


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
    """keysound index -> filename stem."""
    return {i.index: os.path.splitext(i.filename)[0] for i in ezi}


def build_filemap(asset_dir):
    """stem (lowercased) -> path, for every audio file in the asset dir."""
    out = {}
    for fn in os.listdir(asset_dir):
        stem, ext = os.path.splitext(fn)
        if ext.lower() in AUDIO_EXT:
            out[stem.lower()] = os.path.join(asset_dir, fn)
    return out


def resolve_assets(stems, root='extracted_assets', min_score=0.9):
    """Find the extracted_assets/<song_id> whose files match this chart's keysounds.

    Accepts keysound stems or full filenames — the extension is stripped either way. Passing
    `.ezi` filenames verbatim used to score 0 against every directory and silently yield no
    match.
    """
    want = {os.path.splitext(s)[0].lower() for s in stems}
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


def render_one(song_dir, assets, out, rate=44100, gain=1.0, normalize=True, only=None,
               assets_root='extracted_assets', tag=True, song=None):
    """Render one song. Returns a one-line summary, or raises on a hard failure."""
    ez = os.path.join(song_dir, 'ez.ez')
    ezi = os.path.join(song_dir, 'ezi.ezi')
    if not (os.path.exists(ez) and os.path.exists(ezi)):
        raise ValueError('no ez.ez / ezi.ezi in %s' % song_dir)

    ch = parse_ez(load(ez)[0])
    data_ezi, _ = load(ezi)
    idx2stem = build_index(parse_ezi(data_ezi))

    if assets == 'auto':
        assets, score = resolve_assets(list(idx2stem.values()), root=assets_root)
        if not assets:
            raise ValueError('no extracted_assets/* matches (best overlap %.2f)' % score)
    filemap = build_filemap(assets)

    seconds, n_frames = ch.duration, 0
    # Room for the last notes' tails, then trimmed to the last non-silent frame, so a note
    # landing exactly on the final tick is not dropped.
    n_frames = int(np.ceil(seconds * rate)) + 30 * rate
    mix = np.zeros((n_frames, 2), dtype=np.float32)

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
        # float32 accumulation with a single clip at the end; int16 would saturate
        # mid-mix once enough layers overlap.
        mix[off:off + n] += buf[:n] * (vel / 127.0)
        used += 1

    peak = float(np.max(np.abs(mix))) if mix.size else 0.0
    if normalize and peak > 0:
        mix *= (0.99 / peak)
    mix *= gain
    np.clip(mix, -1.0, 1.0, out=mix)

    env = np.abs(mix).max(axis=1)
    last = int(np.argmax(env[::-1] > 1e-6)) if env.size else 0
    if last:
        mix = mix[:len(mix) - last + 1]

    outdir = os.path.dirname(out)
    if outdir:
        os.makedirs(outdir, exist_ok=True)
    sf.write(out, mix, rate, format='FLAC')

    label = chart_label(song_dir)
    name = song or label.get('song')
    written = tag_file(out, name, label) if tag else {}

    warn = ''
    if missing_name:
        warn += ' [%d notes reference unknown keysounds]' % missing_name
    if missing_file:
        warn += ' [%d keysounds absent from assets]' % missing_file
    if tag and not written:
        warn += ' [untagged: song not resolved]'
    return ('%-16s %5d events / %4d keysounds  chart %6.2fs -> %6.2fs%s'
            % (chart_name(song_dir), used, len(cache),
               seconds, len(mix) / rate, warn))


def discover_charts(root):
    """Every directory under `root` holding both ez.ez and ezi.ezi.

    Returns [(path, name)] where `name` is the path relative to `root` with separators
    flattened — captures are nested as <song>/<keymode>/<difficulty>, so the basename alone
    would be just "shd" and collide across songs.
    """
    found = []
    for dirpath, _dirs, files in os.walk(root):
        if 'ez.ez' in files and 'ezi.ezi' in files:
            rel = os.path.relpath(dirpath, root)
            found.append((dirpath, rel.replace(os.sep, '_')))
    return sorted(found)


_PLACEHOLDER_RE = re.compile(r'^song_[0-9a-f]{6,}$')


def slug(s):
    """Filesystem-friendly text: runs of punctuation/space become single underscores."""
    return re.sub(r'[^\w.-]+', '_', song_meta.clean(str(s or '')),
                  flags=re.UNICODE).strip('._')


def song_slug(song_dir):
    """The capture's song name: its title, else its codename, else ''.

    `ident.json` records both the display `title` (from the game's metadata table) and the
    resource codename (`song`, e.g. `HyperMagic`). An unidentified capture has neither, only
    the `song_<hash>` placeholder the dumper fell back to, which is not a name.
    """
    label = chart_label(song_dir)
    for key in ('title', 'song'):
        v = label.get(key)
        if v and not _PLACEHOLDER_RE.match(str(v).strip()):
            return slug(v)
    return ''


def chart_name(song_dir, root='extracted_charts'):
    """A unique, readable name for one capture directory: song plus variant.

    The song comes from the capture's `ident.json` — the display title when the metadata
    table resolved one (`Hyper Magic`), else the resource codename (`HyperMagic`) — so a
    render is named after the song rather than `song_<hash>`. The variant (key mode +
    difficulty) keeps the 4K/5K/6K/8K and EZ/NM/HD/SHD variants of one song from colliding.

    Captures nest as <song>/<keymode>/<difficulty>, so when the label is missing both the
    song and the variant fall back to that path. When the directory is not under the charts
    root, use its last three components, which is exactly that nesting.
    """
    path = os.path.normpath(song_dir)
    try:
        rel = os.path.relpath(path, os.path.normpath(root))
    except ValueError:                              # e.g. a different drive on Windows
        rel = ''
    if not rel or rel.startswith('..') or os.path.isabs(rel):
        rel = os.sep.join(path.split(os.sep)[-3:])
    parts = rel.split(os.sep)

    label = chart_label(song_dir)
    song = song_slug(song_dir) or slug(parts[0])
    variant = [label.get('keymode'), label.get('difficulty')]
    if not any(variant):                            # no label: read the nesting
        variant = parts[1:]
    return '_'.join([song] + [b for b in (slug(v) for v in variant) if b])


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('song_dir', nargs='?', help='directory holding ez.ez and ezi.ezi')
    ap.add_argument('--all', action='store_true',
                    help='render every chart under --charts')
    ap.add_argument('--charts', default='extracted_charts',
                    help='where to look with --all (default extracted_charts)')
    ap.add_argument('--assets', default='auto',
                    help="extracted keysounds for this song, or 'auto' (default)")
    ap.add_argument('-o', '--out', help='output file, or directory when using --all')
    ap.add_argument('--rate', type=int, default=44100)
    ap.add_argument('--gain', type=float, default=1.0)
    ap.add_argument('--no-normalize', action='store_true')
    ap.add_argument('--tracks', help='only these track indices, e.g. 3,4,5,6')
    ap.add_argument('--song', help='song name for tagging (default: the capture label)')
    ap.add_argument('--no-tags', action='store_true', help='skip FLAC metadata')
    args = ap.parse_args()

    only = {int(x) for x in args.tracks.split(',')} if args.tracks else None
    kw = dict(rate=args.rate, gain=args.gain, normalize=not args.no_normalize, only=only,
              tag=not args.no_tags, song=args.song)

    if args.all:
        outdir = args.out or 'rendered_songs'
        charts = discover_charts(args.charts)
        if not charts:
            sys.exit('no charts with ez.ez + ezi.ezi under %s' % args.charts)
        print('rendering %d chart(s) -> %s\n' % (len(charts), outdir))
        ok = skipped = 0
        for d, _name in charts:
            name = chart_name(d)                    # includes the song, unlike the walk name
            out = os.path.join(outdir, name + '.flac')
            try:
                print(render_one(d, args.assets, out, **kw))
                ok += 1
            except Exception as e:
                print('%-16s SKIP: %s' % (os.path.basename(os.path.normpath(d)), e))
                skipped += 1
        print('\n%d rendered, %d skipped' % (ok, skipped))
        return

    if not args.song_dir:
        ap.error('give a song directory, or --all')
    song_dir = args.song_dir
    if not os.path.exists(os.path.join(song_dir, 'ez.ez')):
        found = discover_charts(song_dir)
        if len(found) == 1:
            song_dir = found[0][0]
        elif len(found) > 1:
            ap.error('%s holds %d charts; name one of them or use --all'
                     % (song_dir, len(found)))
    out = args.out or os.path.join('rendered_songs', chart_name(song_dir) + '.flac')
    print(render_one(song_dir, args.assets, out, **kw))


if __name__ == '__main__':
    main()
