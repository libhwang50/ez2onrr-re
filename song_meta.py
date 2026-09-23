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

# The API music list (`c2s_get_gameinfo`) keys every song by the exact resource name the
# chart request carries and gives its numeric MUSIC_ID per game mode. `music_names.json`
# (`da.MUSIC_NAME_DIC`) is keyed by that id and holds the display title/composer, so the
# pair resolves a resource name exactly — no fuzzy title matching needed. Built locally by
# `server/_build_data.py`; when absent we fall back to title matching alone.
MUSIC_LIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'server', 'data', 'gameinfo.json')

# Some titles carry TextMeshPro rich-text markup, e.g.
# 'Change My World <size=80%>(Going Mad Mix)</size>'. Strip it for matching and for tags.
_MARKUP_RE = re.compile(r'<[^>]*>')

# Trailing parenthetical qualifiers that a resource key drops, e.g. 'Air (EZ2ON Ver.)'
# is served as `Air`, and 'Change My World (Going Mad Mix)' as `changemyworld`.
_PAREN_RE = re.compile(r'\s*[\(\[][^()\[\]]*[\)\]]\s*$')

_cache = {}
_list_cache = {}


def clean(s):
    """Remove TextMeshPro rich-text markup and surrounding whitespace."""
    return _MARKUP_RE.sub('', s or '').strip()


def _base(s):
    """Title with trailing parenthetical qualifiers stripped.

    The chart's `musicresourcename` is the title up to the first parenthetical, so
    `Air <size=70%>(EZ2ON Ver.)</size>` is served as `Air`, not `Airwave`.
    """
    out = clean(s)
    while True:
        stripped = _PAREN_RE.sub('', out).strip()
        if stripped == out:
            return out
        out = stripped


def _norm(s):
    """Fold a name for matching: lowercase, alphanumerics only.

    The chart's `musicresourcename` is a resource key, not always the display title — it is
    `hypermagic` where the table says `Hyper Magic` — so exact matching is not enough.
    """
    return ''.join(c for c in str(s).lower() if c.isalnum())


def _word_prefixes(text):
    """Normalized prefixes that end on a word boundary, e.g. 'Change My World' ->
    {'change', 'changemy', 'changemyworld'}. This is what stops `air` from matching
    `airwave` (whose only prefix is the whole word `airwave`)."""
    out, acc = [], ''
    for word in re.split(r'[^A-Za-z0-9]+', text):
        if not word:
            continue
        acc += word.lower()
        out.append(acc)
    return out


def load(path=None):
    """Return {lowercased title: record} plus the raw list, caching by path."""
    path = path or DEFAULT_PATH
    if path in _cache:
        return _cache[path]
    try:
        raw = json.load(open(path))
    except (OSError, ValueError):
        raw = []
    by_name, by_norm, by_base, by_prefix, by_id = {}, {}, {}, {}, {}
    for rec in raw:
        if rec.get('id') is not None:
            by_id.setdefault(rec['id'], rec)
        for key in ('KorName', 'EngName', 'JapName'):
            title_v = clean(rec.get(key))
            if not title_v:
                continue
            by_name.setdefault(title_v.lower(), rec)
            by_norm.setdefault(_norm(title_v), rec)
            base = _base(title_v)
            if not base:
                continue
            by_base.setdefault(_norm(base), rec)
            for pfx in _word_prefixes(base):
                by_prefix.setdefault(pfx, rec)
    _cache[path] = (raw, by_name, by_norm, by_base, by_prefix, by_id)
    return _cache[path]


def load_music_list(path=None):
    """Return {resource name: [musicList entry]}, the folded-name index and {id: entry}.

    `gameinfo.json` is `{musicList: [...]}` and each entry has `TITLE` (the resource name
    the chart request carries), `MUSIC_ID` and `GAME_MODE`. A resource name maps to two
    ids — one per game mode — so the title index keeps a list.
    """
    path = path or MUSIC_LIST_PATH
    if path in _list_cache:
        return _list_cache[path]
    try:
        raw = json.load(open(path))
    except (OSError, ValueError):
        raw = []
    if isinstance(raw, dict):
        raw = raw.get('musicList') or []
    by_title, by_norm, by_id = {}, {}, {}
    for it in raw:
        title_v = str(it.get('TITLE') or '').strip()
        if title_v:
            by_title.setdefault(title_v.lower(), []).append(it)
            by_norm.setdefault(_norm(title_v), []).append(it)
        if it.get('MUSIC_ID') is not None:
            by_id.setdefault(it['MUSIC_ID'], it)
    _list_cache[path] = (raw, by_title, by_norm, by_id)
    return _list_cache[path]


def _by_name_only(name, path=None):
    """Metadata record matched on the localised display titles alone.

    Tries an exact title match, then an alphanumeric-folded one, then a word-boundary
    prefix (`changemyworld` for `Change My World (Going Mad Mix)`, but never `air` for
    `Airwave`).
    """
    if not name:
        return None
    _, index, norm, base, prefix, _by_id = load(path)
    key = str(name).strip().lower()
    n = _norm(key)
    return (index.get(key) or norm.get(n) or base.get(n) or prefix.get(n))


def by_id(music_id, path=None):
    """Metadata record for a numeric music id, or None."""
    if music_id is None:
        return None
    return load(path)[5].get(music_id)


def by_resource(name, gamemode=None, path=None, list_path=None):
    """Metadata record for a chart's `musicresourcename`, the authoritative lookup.

    The API music list keys the resource name directly and gives the MUSIC_ID for each
    game mode, which then keys `da.MUSIC_NAME_DIC` (`music_names.json`). This resolves
    songs whose resource name is nothing like their display title (`E2ofull` ->
    `E2O (Original Mix)`, `Reggae` -> `You love the life you live`) and disambiguates the
    per-game-mode id pairs (`Air` gm1 = 21706, gm2 = 1171). Falls back to title matching.
    """
    if not name:
        return None
    key = str(name).strip().lower()
    _, by_title, by_norm, _by_id = load_music_list(list_path)
    entries = by_title.get(key) or by_norm.get(_norm(key)) or []
    if entries:
        entry = entries[0]
        if gamemode is not None:
            gm = str(gamemode)
            entry = next((e for e in entries if str(e.get('GAME_MODE')) == gm), entry)
        rec = by_id(entry.get('MUSIC_ID'), path)
        if rec:
            return rec
    return _by_name_only(name, path)


def by_name(name, path=None):
    """Metadata record for a song, by resource name or display title.

    Display titles first (so an explicit title still wins), then the exact resource-name
    map from the API music list. The vast majority of callers pass a resource name.
    """
    rec = _by_name_only(name, path)
    if rec:
        return rec
    return by_resource(name, path=path)


def find(name, path=None, limit=8):
    """Fuzzy candidates, for when a resource name cannot be resolved."""
    _, index, norm, _base, _prefix, _by_id = load(path)
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
        raw, index, _norm_idx, _base, _prefix, _by_id = load()
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
