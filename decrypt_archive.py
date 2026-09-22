#!/usr/bin/env python3
"""Complete chart dumps in extracted_charts/ — decrypt the raw CDN captures.

    python decrypt_archive.py             # fill in what is missing
    python decrypt_archive.py --force     # redo every plaintext
    python decrypt_archive.py <dir> ...   # only these directory trees
    python decrypt_archive.py --check     # report only, change nothing

A sweep capture (or a dump whose inline decrypt failed) has the raw CDN
ciphertexts but not the plaintext. This walks the archive and writes the missing

    ez.ez, ezi.ezi            decrypted chart / keysound index
    instrumentDic.json        the .ezi's index -> basename mapping
                              (the same shape dump_song.py writes: [[idx, name], ...])

so a capture ends up indistinguishable from a full dumping-tool dump. Files that
exist are left alone unless --force. Exits non-zero if anything could not be
decrypted, so it can gate a batch.
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import decrypt_chart  # noqa: E402

CIPHERS = {'ez': ('cdn_ez_', 'mem_rjl.bin'), 'ezi': ('cdn_ezi_', 'mem_rjm.bin')}



def find_cipher(d, kind):
    pref, alt = CIPHERS[kind]
    names = sorted(os.listdir(d))
    for n in names:
        if n.startswith(pref):
            return os.path.join(d, n)
    alt_p = os.path.join(d, alt)
    return alt_p if os.path.exists(alt_p) else None


def ezi_mapping(pt: bytes):
    rows = []
    for line in pt.decode('utf-8', 'replace').splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0].isdigit():
            rows.append([int(parts[0]), os.path.splitext(parts[2])[0]])
    return rows


def process(d, force=False, check=False):
    done, skipped, failed = [], [], []
    ident_p = os.path.join(d, 'ident.json')
    ident = {}
    if os.path.exists(ident_p):
        try:
            ident = json.load(open(ident_p))
        except Exception:
            ident = {}
    changed_ident = False
    for kind, out_name in (('ez', 'ez.ez'), ('ezi', 'ezi.ezi')):
        out_p = os.path.join(d, out_name)
        if os.path.exists(out_p) and not force:
            skipped.append(out_name)
            continue
        src = find_cipher(d, kind)
        if src is None:
            failed.append(f'{out_name}: no ciphertext')
            continue
        try:
            pt, pair = decrypt_chart.decrypt_named(open(src, 'rb').read())
        except ValueError as e:
            failed.append(f'{out_name}: {e}')
            continue
        if not check:
            with open(out_p, 'wb') as f:
                f.write(pt)
            if ident.get('chartKeyPair') != pair:
                ident['chartKeyPair'] = pair
                changed_ident = True
        done.append(f'{out_name} ({len(pt)}B, {pair})')
        if kind == 'ezi':
            dic_p = os.path.join(d, 'instrumentDic.json')
            rows = ezi_mapping(pt)
            if rows and (force or not os.path.exists(dic_p)) and not check:
                json.dump(rows, open(dic_p, 'w'), ensure_ascii=False)
                done.append(f'instrumentDic.json ({len(rows)} entries)')
    if changed_ident and not check:
        json.dump(ident, open(ident_p, 'w'), indent=1, ensure_ascii=False)
    return done, skipped, failed


def targets(args):
    """Chart directories, walking whatever was named (so a song dir works too)."""
    bases = args.dirs or [os.path.join(ROOT, 'extracted_charts')]
    out = set()
    for base in bases:
        if not os.path.isdir(base):
            print(f'skip {base}: not a directory')
            continue
        for dirpath, _dirs, files in os.walk(base):
            if (any(f.startswith('cdn_') for f in files)
                    or 'mem_rjl.bin' in files or 'ezi.ezi' in files):
                out.add(dirpath)
    return sorted(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('dirs', nargs='*', help='directories (default: all of extracted_charts/)')
    ap.add_argument('--force', action='store_true', help='redo existing plaintext')
    ap.add_argument('--check', action='store_true', help='report only, write nothing')
    args = ap.parse_args()

    n_done = n_failed = 0
    for d in targets(args):
        done, skipped, failed = process(d, args.force, args.check)
        if not (done or failed):
            continue
        rel = os.path.relpath(d, ROOT)
        print(f'{rel}:')
        for x in done:
            print(f'  + {x}')
            n_done += 1
        for x in failed:
            print(f'  ! {x}')
            n_failed += 1
    print(f'\n{n_done} file(s) written, {n_failed} failure(s)'
          + (' (check only)' if args.check else ''))
    return 1 if n_failed else 0


if __name__ == '__main__':
    sys.exit(main())
