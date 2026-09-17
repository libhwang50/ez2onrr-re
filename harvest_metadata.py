#!/usr/bin/env python3
"""Harvest the game's song metadata table into `music_names.json`.

`da.MUSIC_NAME_DIC` is a `Dictionary<int, da.MUSIC_NAME_DATA>` with 1223 entries holding
the localised titles and the composer:

    KorName / EngName / JapName   titles
    Composer                      the artist
    PtVer                         16 ints, per-key-mode pattern versions
    MaxEye / HiddenBga            flags

It regenerates in a few seconds from a running game, so it is not worth committing; the
file is a cache that `dump_song.py` and `render_song.py` read.

Usage
-----
    python3 harvest_metadata.py [--out music_names.json] [--gadget 127.0.0.1:27042]
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tools'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--out', default='music_names.json')
    ap.add_argument('--gadget', default='127.0.0.1:27042')
    args = ap.parse_args()

    import frida  # imported late so --help works without it

    root = os.path.dirname(os.path.abspath(__file__))
    driver = os.path.join(root, 'tools', 'build', '_musicdic_run.js')
    if not os.path.exists(driver):
        sys.exit('missing %s — run: bash tools/il2cpp/build_run.sh' % driver)

    dev = frida.get_device_manager().add_remote_device(args.gadget)
    session = dev.attach('Gadget')
    script = session.create_script(open(driver).read())
    script.load()
    try:
        entries = script.exports_sync.dumpall()
    finally:
        session.detach()

    if not entries:
        sys.exit('no entries returned — is a song-select screen up?')
    json.dump(entries, open(args.out, 'w'), indent=1, ensure_ascii=False)

    named = sum(1 for e in entries if e.get('KorName') or e.get('EngName'))
    comp = sum(1 for e in entries if e.get('Composer'))
    print('harvested %d entries (%d titled, %d with a composer) -> %s'
          % (len(entries), named, comp, args.out))
    for e in entries[:3]:
        print('  %-8s %-28s %s' % (e.get('id'), e.get('KorName'), e.get('Composer')))


if __name__ == '__main__':
    main()
