#!/usr/bin/env python3
"""Compute the rating from a clearlist and compare it with in-game values.

Sources (pick one):
  --store            server/data/store.db, the private server's live store
  --myinfo PATH      a captured c2s_get_myinfo JSON (default data/myinfo.json)
  --clears JSON      a raw list of {music_id,keymode,levelmode,score,...}

Reported values are passed as `--reported '{"4S":9.434,"4B":8696,...}'` (or a
JSON file path); they are compared side by side with the computed ones.

    python server/re/_rating_check.py --store
    python server/re/_rating_check.py --store --reported '{"4S":9.434,"5S":5.273,
        "6S":7.072,"8S":1.753,"4B":8696,"5B":1528,"6B":2594,"8B":420}'
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))   # server/ -> rating

import rating  # noqa: E402


def clears_from_store(path, steamid=None):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    q = 'SELECT music_id,keymode,levelmode,score FROM clears'
    args = ()
    if steamid:
        q += ' WHERE steamid=?'
        args = (str(steamid),)
    return [dict(r) for r in db.execute(q, args)]


def clears_from_myinfo(path):
    mi = json.load(open(path))
    out = []
    for e in mi.get('clearlist', []):
        mid = e.get('MUSIC_ID')
        if mid is None:
            continue
        scores = str(e.get('SCORE', '')).split(',')
        for idx in range(min(16, len(scores))):
            s = scores[idx].strip()
            if s and s != '0':
                out.append({
                    'music_id': int(mid),
                    'keymode': idx // 4 + 1,
                    'levelmode': idx % 4 + 1,
                    'score': int(float(s)),
                })
    return out


def clears_from_json(path):
    data = json.load(open(path))
    if isinstance(data, dict):
        data = data.get('clears') or data.get('clearlist') or []
    out = []
    for c in data:
        out.append({
            'music_id': int(c.get('music_id') or c.get('MUSIC_ID') or 0),
            'keymode': int(c.get('keymode') or 0),
            'levelmode': int(c.get('levelmode') or 0),
            'score': int(c.get('score') or 0),
        })
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group()
    src.add_argument('--store', action='store_true',
                     help='read server/data/store.db (default)')
    src.add_argument('--myinfo', default=None,
                     help='read a captured c2s_get_myinfo JSON')
    src.add_argument('--clears', default=None, help='read a JSON clear list')
    ap.add_argument('--steamid', default=None, help='limit the store to one user')
    ap.add_argument('--data', default=None, help='override the server data dir')
    ap.add_argument('--reported', default=None,
                    help='in-game values as JSON text or a path')
    args = ap.parse_args()

    data_dir = args.data or os.path.join(os.path.dirname(HERE), 'data')
    db = rating.MusicDB(os.path.join(data_dir, 'gameinfo.json'))

    if args.myinfo:
        clears = clears_from_myinfo(args.myinfo)
        label = args.myinfo
    elif args.clears:
        clears = clears_from_json(args.clears)
        label = args.clears
    else:
        clears = clears_from_store(os.path.join(data_dir, 'store.db'), args.steamid)
        label = 'store.db' + (f' ({args.steamid})' if args.steamid else '')
    print(f'source: {label}  ({len(clears)} clears)')

    reported = None
    if args.reported:
        if os.path.exists(args.reported):
            reported = json.load(open(args.reported))
        else:
            reported = json.loads(args.reported)
        reported = {str(k).upper(): float(v) for k, v in reported.items()}

    for mode, label2 in (('standard', 'S'), ('basic', 'B')):
        vals = rating.format_ratings(rating.ratings(db, clears, mode), mode)
        print(f'  {mode:8}:', '  '.join(f'{k}{label2}={vals[k]}'
                                         for k in sorted(vals, key=int)))
    if reported:
        print('  reported:', '  '.join(f'{k}={reported[k]}'
                                        for k in sorted(reported, key=lambda k: (k[-1], k[:-1]))))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
