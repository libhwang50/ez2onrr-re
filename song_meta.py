#!/usr/bin/env python3
"""Look up song metadata (title, composer) captured by `harvest_metadata.py`.

The game's `da.MUSIC_NAME_DIC` maps a numeric music id to a `MUSIC_NAME_DATA` record. The
chart's `musicresourcename` (e.g. "Rebind") matches those records' titles, so a song can be
resolved by name without needing its id.

`music_names.json` is a cache: regenerate it from a running game with
`python3 harvest_metadata.py`.

Used by `dump_song.py` (to record metadata next to a capture) and `render_song.py` (to tag
the rendered FLAC).
"""
import json
import os
import re

DEFAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'music_names.json')

# Some titles carry TextMeshPro rich-text markup, e.g.
# 'Change My World <size=80%>(Going Mad Mix)</size>'. Strip it for matching and for tags.
_MARKUP_RE = re.compile(r'<[^>]*>')

_cache = {}


def clean(s):
    """Remove TextMeshPro rich-text markup and surrounding whitespace."""
    return _MARKUP_RE.sub('', s or '').strip()


def _norm(s):
    """Fold a name for matching: lowercase, alphanumerics only.

    The chart's `musicresourcename` is a resource key, not always the display title — it is
    `hypermagic` where the table says `Hyper Magic` — so exact matching is not enough.
    """
    return ''.join(c for c in str(s).lower() if c.isalnum())


def load(path=None):
    """Return {lowercased title: record} plus the raw list, caching by path."""
    path = path or DEFAULT_PATH
    if path in _cache:
        return _cache[path]
    try:
        raw = json.load(open(path))
    except (OSError, ValueError):
        raw = []
    by_name, by_norm = {}, {}
    for rec in raw:
        for key in ('KorName', 'EngName', 'JapName'):
            title_v = clean(rec.get(key))
            if title_v:
                by_name.setdefault(title_v.lower(), rec)
                by_norm.setdefault(_norm(title_v), rec)
    _cache[path] = (raw, by_name, by_norm)
    return _cache[path]


def by_name(name, path=None):
    """Metadata record for a song, matched on any of its localised titles.

    Tries an exact title match, then an alphanumeric-folded one, then a prefix match — the
    resource key is often a truncation of the display title (`changemyworld` for
    `Change My World (Going Mad Mix)`). The shortest matching title wins, so a general key
    does not grab a longer, different song.
    """
    if not name:
        return None
    _, index, norm = load(path)
    key = str(name).strip().lower()
    hit = index.get(key) or norm.get(_norm(key))
    if hit:
        return hit
    n = _norm(key)
    if not n:
        return None
    best = None
    for full, rec in norm.items():
        if full.startswith(n) and (best is None or len(full) < best[0]):
            best = (len(full), rec)
    return best[1] if best else None


def find(name, path=None, limit=8):
    """Fuzzy candidates, for when a resource name cannot be resolved."""
    _, index, norm = load(path)
    n = _norm(name)
    if not n:
        return []
    out = []
    for rec in (index.values()):
        t = _norm(title(rec) or '')
        if t and (n in t or t in n):
            out.append(rec)
        if len(out) >= limit:
            break
    return out


def title(rec, prefer=('KorName', 'EngName', 'JapName')):
    for key in prefer:
        v = clean((rec or {}).get(key))
        if v:
            return v
    return None


def tags(name, album='EZ2ON REBOOT: R', path=None):
    """Vorbis-comment tags for a song, or {} if there is no metadata."""
    rec = by_name(name, path)
    if not rec:
        return {}
    out = {'album': album}
    t = title(rec)
    if t:
        out['title'] = t
    if rec.get('Composer'):
        out['artist'] = rec['Composer']
    for key, tag in (('KorName', 'title_kr'), ('EngName', 'title_en'), ('JapName', 'title_jp')):
        v = clean(rec.get(key))
        if v and v != t:
            out[tag] = v
    if rec.get('id'):
        out['comment'] = 'music id %s' % rec['id']
    return out


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        raw, index, _norm_idx = load()
        print('%d records, %d distinct titles' % (len(raw), len(index)))
        for name in list(index)[:10]:
            rec = index[name]
            print('  %-30s %-20s id=%s' % (rec.get('KorName'), rec.get('Composer'), rec.get('id')))
    else:
        for name in sys.argv[1:]:
            rec = by_name(name)
            if rec:
                print('%-24s %s  [%s]' % (name, rec.get('KorName'), rec.get('Composer')))
            else:
                cand = find(name)
                print('%-24s NOT FOUND%s' % (name, ('  candidates: ' + ', '.join(
                    title(c) or '?' for c in cand)) if cand else ''))
