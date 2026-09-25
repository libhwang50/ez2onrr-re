"""EZ2ON REBOOT:R rating calculation (reverse-engineered, exact for Standard).

The client computes the per-key-mode rating locally in ``da.cii`` (Standard) and
stores it in ``da.rvz`` (float[4], key modes 4/5/6/8); Basic lives in
``da.rwc`` (int[4]).  The algorithm, read from the live disassembly and the
client's own data tables:

  * ``da.rwg`` is the real category table (7 groups), each with a ``COUNT`` and
    a ``RATIO`` (``da.cu`` fields at +0x18/+0x1c).  It is *not* the gameinfo
    ``ratioCategoryList`` the server advertises.
  * Per difficulty, the client keeps a rating point ``rks[d]`` (``da.cr`` +0xa0)
    computed on each play as::

        rks = weighted_level + adjustment / 10

    where ``weighted_level`` is ``gameinfo LEVEL / 10`` (the 불렙 weights are
    already baked into ``LEVEL``, e.g. Be-at Feedback 4K SHD = 163 -> 16.3) and
    ``adjustment`` is the fine score table (NamuWiki §3.1; -40 … +22).
  * One key mode's rating is the **average over the 7 categories** of
    ``(sum of that category's top-COUNT rks) / COUNT * RATIO``::

        rating = (1/7) * Σ_cat  (topCOUNT(rks in cat) summed / COUNT_cat) * RATIO_cat

    The 4 difficulties of a key mode all contribute.  The value is on the same
    scale as the in-game display (no extra /1000).

Weights, categories and the score table all come from the data we already have;
only the client's local play list is needed as input.
"""
from __future__ import annotations

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get('EZ2_DATA') or os.path.join(HERE, 'data')

KM_CHARS = {1: '4', 2: '5', 3: '6', 4: '8', 5: '7'}
N_CATEGORIES = 7

# (versions, COUNT, RATIO) — read from the live `da.rwg`.
CATEGORIES = [
    ((1, 2, 3, 4, 5, 6, 7), 10, 0.80),
    ((8, 20, 21, 24, 33), 10, 0.80),
    ((26, 27), 10, 0.80),
    ((22, 25), 15, 1.22),
    ((23, 28, 32), 18, 1.46),
    ((29, 30, 31), 12, 0.92),
    ((34, 35, 36), 15, 1.36),
]

# Fine score table (NamuWiki §3.1), step function on raw score.  Values are the
# `adjustment` in the rks formula above.
SCORE_STEPS = [
    (1090000, 22.0), (1080000, 21.5), (1070000, 21.0), (1060000, 20.5),
    (1050000, 20.0), (1037500, 15.0), (1025000, 10.0), (1012500, 5.0),
    (1000000, 0.0), (987500, -5.0), (975000, -10.0), (962500, -15.0),
    (950000, -20.0), (925000, -25.0), (900000, -30.0), (875000, -35.0),
    (850000, -40.0), (750000, -50.0), (650000, -60.0), (550000, -70.0),
]


def adjustment(score):
    score = int(score or 0)
    for threshold, value in SCORE_STEPS:
        if score >= threshold:
            return value
    return SCORE_STEPS[-1][1]


def _version_category(version):
    for i, (versions, _count, _ratio) in enumerate(CATEGORIES):
        if version in versions:
            return i
    return -1


class MusicDB:
    """The gameinfo fields the rating needs, plus the version->category map."""

    def __init__(self, gameinfo_path=None):
        self.path = gameinfo_path or os.path.join(DATA, 'gameinfo.json')
        gi = json.load(open(self.path))
        self.levels = {}     # music_id -> [16] ints (internal, level*10)
        self.versions = {}   # music_id -> int VERSION
        self.gamemode = {}   # music_id -> 1 Standard / 2 Basic
        for m in gi.get('musicList', []):
            mid = m['MUSIC_ID']
            self.levels[mid] = [int(x) for x in str(m.get('LEVEL', '')).split(',')]
            try:
                self.versions[mid] = int(m.get('VERSION') or 0)
            except (TypeError, ValueError):
                self.versions[mid] = 0
            self.gamemode[mid] = int(m.get('GAME_MODE') or 0)

    def weighted_level(self, music_id, keymode, levelmode):
        """Displayed (weight-included) level for a variant, or 0."""
        arr = self.levels.get(music_id)
        idx = (int(keymode) - 1) * 4 + (int(levelmode) - 1)
        if arr and 0 <= idx < len(arr):
            return arr[idx] / 10.0
        return 0.0


def chart_point(db, clear):
    """One cleared variant's `rks` value: weighted level + adjustment/10."""
    mid = int(clear.get('music_id') or 0)
    level = db.weighted_level(mid, clear.get('keymode'), clear.get('levelmode'))
    score = int(clear.get('score') or 0)
    if level <= 0 or score <= 0:
        return None
    return level + adjustment(score) / 10.0


def keymode_rating(db, clears, keymode, want_gamemode=1):
    """`(1/7) * Σ_cat (top-COUNT sum / COUNT * RATIO)` for one key mode."""
    by_cat = {}
    for c in clears:
        if int(c.get('keymode') or 0) != keymode:
            continue
        mid = int(c.get('music_id') or 0)
        if db.gamemode.get(mid) != want_gamemode:
            continue
        cat = _version_category(db.versions.get(mid, 0))
        if cat < 0:
            continue
        p = chart_point(db, c)
        if p is None:
            continue
        by_cat.setdefault(cat, []).append(p)
    total = 0.0
    for cat, points in by_cat.items():
        _versions, count, ratio = CATEGORIES[cat]
        total += sum(sorted(points, reverse=True)[:count]) / count * ratio
    return total / N_CATEGORIES


def ratings(db, clears, mode='standard'):
    """`{keymode_char: value}` for a mode, matching the in-game display."""
    want = 2 if mode == 'basic' else 1
    return {ch: keymode_rating(db, clears, km, want)
            for km, ch in KM_CHARS.items()}


def format_ratings(values, mode='standard'):
    if mode == 'basic':
        return {k: int(round(v * 1000)) for k, v in values.items()}
    return {k: round(v, 3) for k, v in values.items()}
