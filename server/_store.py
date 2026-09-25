"""Per-user progression store (SQLite) for the private server.

Built on the **real** `c2s_get_myinfo` capture (`server/data/myinfo.json`), whose
schema is fixed by the client's DTOs:

* `memberinfo` = `MEMBER_ID STATUS PLATE ACC_DATE REG_DATE ROUND LEVEL EXP
  NEXT_EXP RATING`
* `clearlist`  = one entry per `MUSIC_ID`, each with 16-wide CSV arrays
  (`LAMP SCORE RATE COMBO KOOL_JUDGEMENT COOL_JUDGEMENT GOOD_JUDGEMENT
  MISS_JUDGEMENT FAIL_JUDGEMENT PLAY_COUNT`)

The 16 columns are **keymode-major**: `idx = (keymode-1)*4 + (levelmode-1)`, with
the API's 1-based keymode (1=4K, 2=5K, 3=6K…) and levelmode (1=EZ…4=SHD).  The DB
normalises that to one row per cleared variant, which is what `c2s_set_game_clear`
and the rank `plf…` upload carry, and reassembles the arrays when serving.

Single-user today, multi-user by construction: everything is keyed by SteamID.
"""
import os
import sqlite3
import threading
import time

TOP = ('MEMBER_ID', 'STATUS', 'PLATE', 'ACC_DATE', 'REG_DATE', 'ROUND',
       'LEVEL', 'EXP', 'NEXT_EXP', 'RATING')
# clearlist array name -> (default text, formatter)
_ARRAYS = {
    'LAMP': ('0', lambda v: str(int(v))),
    'SCORE': ('0', lambda v: str(int(v))),
    'RATE': ('0.00', lambda v: f'{float(v):.2f}'),
    'COMBO': ('0', lambda v: str(int(v))),
    'KOOL_JUDGEMENT': ('0', lambda v: str(int(v))),
    'COOL_JUDGEMENT': ('0', lambda v: str(int(v))),
    'GOOD_JUDGEMENT': ('0', lambda v: str(int(v))),
    'MISS_JUDGEMENT': ('0', lambda v: str(int(v))),
    'FAIL_JUDGEMENT': ('0', lambda v: str(int(v))),
    'PLAY_COUNT': ('0', lambda v: str(int(v))),
}
# clearlist array name -> clears column
_COLS = {
    'LAMP': 'lamp', 'SCORE': 'score', 'RATE': 'rate', 'COMBO': 'combo',
    'KOOL_JUDGEMENT': 'kool', 'COOL_JUDGEMENT': 'cool',
    'GOOD_JUDGEMENT': 'good', 'MISS_JUDGEMENT': 'miss',
    'FAIL_JUDGEMENT': 'fail', 'PLAY_COUNT': 'play_count',
}
_SCHEMA = """
CREATE TABLE IF NOT EXISTS players (
    steamid   TEXT PRIMARY KEY,
    member_id INTEGER DEFAULT 0,
    status    INTEGER DEFAULT 0,
    plate     INTEGER DEFAULT 1,
    acc_date  TEXT DEFAULT '',
    reg_date  TEXT DEFAULT '',
    round     INTEGER DEFAULT 0,
    level     INTEGER DEFAULT 1,
    exp       INTEGER DEFAULT 0,
    next_exp  INTEGER DEFAULT 0,
    rating    REAL    DEFAULT 0.0,
    updated   REAL
);
CREATE TABLE IF NOT EXISTS clears (
    steamid    TEXT NOT NULL,
    music_id   INTEGER NOT NULL,
    keymode    INTEGER NOT NULL,
    levelmode  INTEGER NOT NULL,
    lamp       INTEGER DEFAULT 0,
    score      INTEGER DEFAULT 0,
    rate       REAL    DEFAULT 0.0,
    combo      INTEGER DEFAULT 0,
    kool       INTEGER DEFAULT 0,
    cool       INTEGER DEFAULT 0,
    good       INTEGER DEFAULT 0,
    miss       INTEGER DEFAULT 0,
    fail       INTEGER DEFAULT 0,
    play_count INTEGER DEFAULT 0,
    updated    REAL,
    PRIMARY KEY (steamid, music_id, keymode, levelmode)
);
CREATE TABLE IF NOT EXISTS accounts (
    id           TEXT PRIMARY KEY,   -- canonical, SteamID-shaped public id
    token_hash   TEXT UNIQUE,        -- sha256 hex of the bearer token
    provider     TEXT DEFAULT '',    -- 'admin' | 'discord' | 'steam' | ''
    provider_id  TEXT DEFAULT '',
    display_name TEXT DEFAULT '',
    created      REAL,
    last_seen    REAL,
    banned       INTEGER DEFAULT 0
);
"""


def slot(keymode, levelmode):
    """The 16-wide clearlist index for one variant (keymode-major)."""
    return (int(keymode) - 1) * 4 + (int(levelmode) - 1)


def new_pseudo_steamid():
    """A 17-digit, SteamID64-shaped id for accounts with no real SteamID.

    Used for Discord/admin accounts and for the Goldberg path, where the
    launcher writes it into the emulator's config so the client presents the
    same id the server assigned."""
    import random
    return '7656119' + f'{random.randrange(10 ** 10):010d}'


class Store:
    def __init__(self, path):
        self.path = path
        self._lock = threading.RLock()
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.executescript(_SCHEMA)
            self._db.commit()

    # -- players ----------------------------------------------------------
    def player(self, steamid):
        with self._lock:
            r = self._db.execute('SELECT * FROM players WHERE steamid=?',
                                 (str(steamid),)).fetchone()
        return dict(r) if r else None

    def upsert_player(self, steamid, **fields):
        steamid = str(steamid)
        with self._lock:
            if self.player(steamid) is None:
                self._db.execute('INSERT INTO players(steamid, updated) VALUES(?,?)',
                                 (steamid, time.time()))
            if fields:
                cols = ', '.join(f'{k}=?' for k in fields)
                self._db.execute(
                    f'UPDATE players SET {cols}, updated=? WHERE steamid=?',
                    (*fields.values(), time.time(), steamid))
            self._db.commit()
        return self.player(steamid)

    def touch_player(self, steamid):
        """Create a default row if absent (so every login has a profile)."""
        if self.player(steamid) is None:
            now = time.strftime('%Y-%m-%dT%H:%M:%S')
            self.upsert_player(steamid, acc_date=now, reg_date=now,
                               member_id=int(steamid) % 1_000_000)
        return self.player(steamid)

    def memberinfo(self, steamid):
        p = self.player(steamid) or {}
        return {k: p.get(k.lower(), 0 if k != 'RATING' else 0.0)
                for k in TOP} | {'RATING': float(p.get('rating') or 0.0)}

    # -- clears -----------------------------------------------------------
    def upsert_clear(self, steamid, music_id, keymode, levelmode, **vals):
        """Insert/update one variant.  Only the keys present in `vals` change."""
        steamid = str(steamid)
        cols = ['steamid', 'music_id', 'keymode', 'levelmode', 'updated']
        args = [steamid, int(music_id), int(keymode), int(levelmode), time.time()]
        for col in ('lamp', 'score', 'rate', 'combo', 'kool', 'cool',
                    'good', 'miss', 'fail', 'play_count'):
            if col in vals:
                cols.append(col)
                args.append(vals[col])
        placeholders = ','.join('?' * len(cols))
        updates = ', '.join(f'{c}=excluded.{c}' for c in cols[1:])
        with self._lock:
            self._db.execute(
                f'INSERT INTO clears({",".join(cols)}) VALUES({placeholders}) '
                f'ON CONFLICT(steamid,music_id,keymode,levelmode) DO UPDATE SET {updates}',
                args)
            self._db.commit()

    def leaderboard(self, music_id, keymode, levelmode, limit=100, page=0,
                    steamid=None):
        """Ranked `(rank, steamid, score)` for one variant — the body the rank
        host's `get<music_id><keymode><levelmode>,<page>[,<steamid>]` wants.

        Page 0 is the Top `limit`; a page with a steamid is that player's
        `limit`-wide window centred on their own rank (the real MyRange was 50
        before / 49 after).  Returns `(rows, total)`; `total` is 0 only when the
        variant has no local scores at all (the caller may then fall back to a
        captured CSV)."""
        with self._lock:
            rs = self._db.execute(
                'SELECT steamid, score FROM clears WHERE music_id=? AND '
                'keymode=? AND levelmode=? AND score>0 '
                'ORDER BY score DESC, updated ASC',
                (int(music_id), int(keymode), int(levelmode))).fetchall()
        entries = [(i, r['steamid'], r['score']) for i, r in enumerate(rs)]
        total = len(entries)
        if not total:
            return [], 0
        if page and steamid is not None:
            idx = next((i for i, sid, _ in entries if str(sid) == str(steamid)), None)
            if idx is None:
                return [], total
            start = max(0, idx - limit // 2)
            return entries[start:start + limit], total
        return entries[:limit], total

    def all_clears(self, steamid):
        """Every clear row for a player (the normalised rating input)."""
        with self._lock:
            rows = self._db.execute('SELECT * FROM clears WHERE steamid=?',
                                    (str(steamid),)).fetchall()
        return [dict(r) for r in rows]

    def clear(self, steamid, music_id, keymode, levelmode):
        with self._lock:
            r = self._db.execute(
                'SELECT * FROM clears WHERE steamid=? AND music_id=? AND '
                'keymode=? AND levelmode=?',
                (str(steamid), int(music_id), int(keymode), int(levelmode))).fetchone()
        return dict(r) if r else None

    def record_clear(self, steamid, music_id, keymode, levelmode, *, lamp=0,
                     score=0, rate=0.0, combo=0, kool=0, cool=0, good=0,
                     miss=0, fail=0):
        """Apply one play (from set_game_clear / plf) to the best-of record.

        The client sends the just-played attempt, so keep the best score's
        statistics, never downgrade the lamp, and always bump play_count.
        """
        cur = self.clear(steamid, music_id, keymode, levelmode)
        best = cur is None or int(score or 0) >= (cur['score'] or 0)
        vals = {
            'lamp': max(int(lamp or 0), (cur or {}).get('lamp') or 0),
            'play_count': ((cur or {}).get('play_count') or 0) + 1,
        }
        if best:
            vals.update(score=int(score or 0), rate=float(rate or 0.0),
                        combo=int(combo or 0), kool=int(kool or 0),
                        cool=int(cool or 0), good=int(good or 0),
                        miss=int(miss or 0), fail=int(fail or 0))
        self.upsert_clear(steamid, music_id, keymode, levelmode, **vals)
        return self.clear(steamid, music_id, keymode, levelmode)

    def clearlist(self, steamid):
        """Rebuild the client's `clearlist` (one entry per MUSIC_ID, 16-wide)."""
        with self._lock:
            rows = self._db.execute('SELECT * FROM clears WHERE steamid=?',
                                    (str(steamid),)).fetchall()
        by_song = {}
        for r in rows:
            idx = slot(r['keymode'], r['levelmode'])
            if not 0 <= idx < 16:
                continue
            arrs = by_song.setdefault(r['music_id'],
                                      {name: [d] * 16 for name, (d, _f) in _ARRAYS.items()})
            for name, col in _COLS.items():
                assert 0 <= idx < 16, (name, idx)
                arrs[name][idx] = _ARRAYS[name][1](r[col])
        out = []
        for mid in sorted(by_song):
            e = {'MUSIC_ID': mid}
            e.update({name: ','.join(vals) for name, vals in by_song[mid].items()})
            out.append(e)
        return out

    def seed_myinfo(self, steamid, myinfo):
        """Import a captured `c2s_get_myinfo` (one-time).  Idempotent per player."""
        steamid = str(steamid)
        mi = myinfo.get('memberinfo', {})
        self.upsert_player(
            steamid,
            member_id=int(mi.get('MEMBER_ID', 0)),
            status=int(mi.get('STATUS', 0)),
            plate=int(mi.get('PLATE', 1)),
            acc_date=mi.get('ACC_DATE', ''),
            reg_date=mi.get('REG_DATE', mi.get('REG_DATA', '')),
            round=int(mi.get('ROUND', 0)),
            level=int(mi.get('LEVEL', 1)),
            exp=int(mi.get('EXP', 0)),
            next_exp=int(mi.get('NEXT_EXP', 0)),
            rating=float(mi.get('RATING', 0.0)),
        )
        n = 0
        for e in myinfo.get('clearlist', []):
            mid = e.get('MUSIC_ID')
            if mid is None:
                continue
            for idx in range(16):
                keymode, levelmode = idx // 4 + 1, idx % 4 + 1
                vals = {}
                for name, col in _COLS.items():
                    arr = str(e.get(name, '')).split(',')
                    if idx < len(arr) and arr[idx] not in ('', '0', '0.00'):
                        vals[col] = float(arr[idx]) if col == 'rate' else int(arr[idx])
                if vals:
                    self.upsert_clear(steamid, mid, keymode, levelmode, **vals)
                    n += 1
        return n

    # -- accounts ---------------------------------------------------------
    def account(self, account_id):
        with self._lock:
            r = self._db.execute('SELECT * FROM accounts WHERE id=?',
                                 (str(account_id),)).fetchone()
        return dict(r) if r else None

    def account_by_token_hash(self, token_hash):
        if not token_hash:
            return None
        with self._lock:
            r = self._db.execute('SELECT * FROM accounts WHERE token_hash=?',
                                 (str(token_hash),)).fetchone()
        return dict(r) if r else None

    def account_by_provider(self, provider, provider_id):
        with self._lock:
            r = self._db.execute(
                'SELECT * FROM accounts WHERE provider=? AND provider_id=?',
                (str(provider), str(provider_id))).fetchone()
        return dict(r) if r else None

    def issue_account(self, token_hash, *, account_id=None, provider='',
                      provider_id='', display_name='', steamid=None):
        """Create an account.  The public id is `steamid` if given (real Steam),
        else a generated pseudo-SteamID (Discord/admin/Goldberg)."""
        aid = str(steamid or account_id or '') or new_pseudo_steamid()
        while self.account(aid) is not None:
            aid = new_pseudo_steamid()
        now = time.time()
        with self._lock:
            self._db.execute(
                'INSERT INTO accounts(id, token_hash, provider, provider_id, '
                'display_name, created, last_seen) VALUES(?,?,?,?,?,?,?)',
                (aid, token_hash, provider, str(provider_id), display_name,
                 now, now))
            self._db.commit()
        return self.account(aid)

    def update_account(self, account_id, **fields):
        if not fields:
            return self.account(account_id)
        cols = ', '.join(f'{k}=?' for k in fields)
        with self._lock:
            self._db.execute(f'UPDATE accounts SET {cols} WHERE id=?',
                             (*fields.values(), str(account_id)))
            self._db.commit()
        return self.account(account_id)

    def touch_account(self, account_id):
        self.update_account(account_id, last_seen=time.time())

    def accounts(self):
        with self._lock:
            rows = self._db.execute(
                'SELECT * FROM accounts ORDER BY created').fetchall()
        return [dict(r) for r in rows]
