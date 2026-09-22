#!/usr/bin/env python3
"""Decrypt EZ2ON REBOOT: R chart payloads (.ez charts / .ezi keysound indexes).

The CDN payload cipher, recovered from `InGameCore.dcf` -> `InGameCore.dcg`:

  1. a data-independent 64-round XOR mask, one pass per byte, built from the
     static tables `InGameCore.svq` (64 B) and `InGameCore.svr` (16 B);
  2. AES-256-CBC / PKCS7. There are **three** static key/IV pairs in `InGameCore`
     (`svk`/`svl`, `svm`/`svn`, `svo`/`svp`); the game records no indication of
     which one a payload used, and exactly one yields a plausible plaintext, so the
     pair is selected by validation (`--keypair` forces one).

Both stages operate in place on the whole buffer, so decryption is
`AES_CBC_decrypt(unmask(ciphertext))`.

Usage:
    python3 decrypt_chart.py <file> [more files...]      # -> <file>.dec
    python3 decrypt_chart.py --out DIR <file> ...
    python3 decrypt_chart.py --inspect <file>            # header summary only
    python3 decrypt_chart.py --archive [DIR ...]         # a whole capture archive

`--archive` walks a tree of `dump_song.py` / sweep captures and fills in the plaintext
(`ez.ez`, `ezi.ezi`, `instrumentDic.json`) for every raw CDN capture that is missing it,
so a sweep capture becomes indistinguishable from a full dump. `--check` audits without
writing and `--force` redoes existing plaintext; the exit code gates a batch.

Payloads that are already plaintext are passed through untouched: the short XML error
body the CDN serves when a signed URL has expired, an already-decrypted `.ez` (`EZFF`),
or an already-decrypted `.ezi` (printable `<index> <velocity> <filename>` lines).
"""
import argparse
import json
import os
import struct
import sys

try:                                    # pycryptodome (the .venv)
    from Crypto.Cipher import AES

    def _aes_decrypt(key, iv, data):
        return AES.new(key, AES.MODE_CBC, iv).decrypt(data)
except ImportError:                     # cryptography (mitmproxy's environment,
    from cryptography.hazmat.primitives.ciphers import (  # e.g. the server addon)
        Cipher, algorithms, modes)

    def _aes_decrypt(key, iv, data):
        d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return d.update(data) + d.finalize()

# Static InGameCore fields. These are compile-time constants baked into the
# assembly's static-field initializers, so they are identical across runs;
# `keybytes.json`, harvested in an earlier session, matches live memory byte-for-byte.
SVQ = bytes.fromhex('31a3e172df7b44db465c84ad28f5a5a5'
                    '9875772fab5a062a8c2e44cfe8a5ba4'
                    '41e68ecdb8ccdfcce716c5268f097549'
                    '04192c9912759d1780a7a7705737fc6ca')
SVR = bytes.fromhex('d0d9223422c56c6ce10496cc0a44777d')

# Three static (key, IV) pairs. The game records no indication of which one a payload
# uses; exactly one of them yields valid PKCS7 for any given chart, so we select by
# validation. All three are in wide use — across the archive, 62 songs use svk/svl,
# 52 use svm/svn and 57 use svo/svp, and 8 songs mix pairs across their variants
# (kamui uses all three), so the choice is not even per-song.
KEYPAIRS = {
    'svk/svl': (bytes.fromhex('b6267ea195763df32ec91ed39d7f6603'
                              '5ca002de4dee12fff9cf93ed92163e0d'),
                bytes.fromhex('8c8e78a8cae9885cc5438b58e2931609')),
    'svm/svn': (bytes.fromhex('1c041e8ebb58fdb485deb781fa756696'
                              'a45ff1bf1ba7d9e85663a01c62bb1f2b'),
                bytes.fromhex('8e763cd2a4d409d62658d626c06f027c')),
    'svo/svp': (bytes.fromhex('7dbb2047f7def50c7c30a7709f6b4bac'
                              '1dc3aebee52f455fe801a32b29518b1d'),
                bytes.fromhex('0d1a6bcb9c80f1b53bdaf766ed40012f')),
}

# Back-compat aliases (the pair identified first).
SVO, SVP = KEYPAIRS['svo/svp']

assert len(SVQ) == 64 and len(SVR) == 16
assert all(len(k) == 32 and len(iv) == 16 for k, iv in KEYPAIRS.values())

# S[i] = svr[svq[i] & 0xf] ^ svq[i]
_SBOX = bytes(SVR[SVQ[i] & 0xF] ^ SVQ[i] for i in range(64))

_MASK_CACHE = []


def mask_byte(ebx: int) -> int:
    """Exact reimplementation of the dcf inner loop for element index ebx."""
    v = 0
    lo = ebx & 0xFF
    for i in range(64):
        r = (ebx * i) % 255          # x86 signed /255 idiom, floor for x >= 0
        if r % 10 == 0:              # cmove r15d, 12
            r = 12
        v ^= _SBOX[i] ^ r ^ lo
    return v


def _mask(n: int) -> bytes:
    while len(_MASK_CACHE) < n:
        _MASK_CACHE.append(mask_byte(len(_MASK_CACHE)))
    return bytes(_MASK_CACHE[:n])


def unmask(buf: bytes) -> bytes:
    m = _mask(len(buf))
    return bytes(b ^ m[i] for i, b in enumerate(buf))


def valid_pkcs7(buf: bytes) -> bool:
    pad = buf[-1] if buf else 0
    return 1 <= pad <= 16 and buf[-pad:] == bytes([pad]) * pad


def plausible(pt: bytes) -> bool:
    """Does this look like a chart (EZFF) or a keysound index?"""
    return pt[:4] == b'EZFF' or looks_like_ezi(pt)


def decrypt(buf: bytes, keypair: str = None) -> bytes:
    """Decrypt a CDN payload.

    `keypair` names an entry of KEYPAIRS (e.g. 'svk/svl'). When omitted, each pair is
    tried and the one whose plaintext has valid PKCS7 padding *and* looks like a chart
    or index is returned. Raises ValueError if none matches.
    """
    data = unmask(buf)
    if keypair is not None:
        key, iv = KEYPAIRS[keypair]
        return _aes_decrypt(key, iv, data)
    padded = []
    for name, (key, iv) in KEYPAIRS.items():
        pt = _aes_decrypt(key, iv, data)
        if valid_pkcs7(pt):
            padded.append(name)
            if plausible(pt):
                return pt
    raise ValueError('no static key pair produced a plausible plaintext'
                     + (' (valid padding but implausible: %s)' % ', '.join(padded)
                        if padded else ''))


def decrypt_named(buf: bytes):
    """Like decrypt(), but returns (plaintext, keypair_name)."""
    for name, (key, iv) in KEYPAIRS.items():
        pt = _aes_decrypt(key, iv, unmask(buf))
        if valid_pkcs7(pt) and plausible(pt):
            return pt, name
    raise ValueError('no static key pair produced a plausible plaintext')


def looks_like_ezi(pt: bytes) -> bool:
    """A decrypted keysound index: printable ASCII lines starting with a digit."""
    head = pt[:64]
    return (len(head) >= 64 and head[:1].isdigit()
            and all(9 <= c <= 126 or c in (10, 13) for c in head))


def is_plaintext(buf: bytes) -> bool:
    return buf[:5] == b'<?xml' or buf[:4] == b'EZFF' or looks_like_ezi(buf)


def describe(pt: bytes) -> str:
    if pt[:5] == b'<?xml':
        return 'plaintext XML error body (%d B)' % len(pt)
    if pt[:4] != b'EZFF':
        return 'NOT EZFF (head %s)' % pt[:8].hex()
    name = pt[6:0x46].split(b'\0')[0].decode('latin-1', 'replace')
    bpm = struct.unpack_from('<f', pt, 0x88)[0] if len(pt) >= 0x8C else 0.0
    tracks = struct.unpack_from('<H', pt, 0x8C)[0] if len(pt) >= 0x8E else 0
    ticks = struct.unpack_from('<I', pt, 0x8E)[0] if len(pt) >= 0x92 else 0
    return ('EZFF chart: v%d name=%r bpm=%.2f ticks/measure=0x%02x tracks=%d '
            'total_ticks=%d EZTR=%d'
            % (pt[5], name, bpm, pt[0x86] if len(pt) > 0x86 else 0, tracks, ticks,
               pt.count(b'EZTR')))


def summarize(pt: bytes) -> str:
    if pt[:4] == b'EZFF':
        return describe(pt)
    if looks_like_ezi(pt):
        return 'ezi keysound index (%d lines): %r' % (pt.count(b'\n'), pt[:32])
    return describe(pt)


# --- archive mode: fill in the plaintext for a tree of raw CDN captures -----------------

CIPHERS = {'ez': ('cdn_ez_', 'mem_rjl.bin'), 'ezi': ('cdn_ezi_', 'mem_rjm.bin')}


def find_cipher(d, kind):
    """The raw ciphertext for `kind` ('ez'/'ezi') in a capture directory, if any."""
    pref, alt = CIPHERS[kind]
    for n in sorted(os.listdir(d)):
        if n.startswith(pref):
            return os.path.join(d, n)
    alt_p = os.path.join(d, alt)
    return alt_p if os.path.exists(alt_p) else None


def ezi_mapping(pt: bytes):
    """[[index, basename], ...] from a decrypted `.ezi`, the shape dump_song.py writes."""
    rows = []
    for line in pt.decode('utf-8', 'replace').splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0].isdigit():
            rows.append([int(parts[0]), os.path.splitext(parts[2])[0]])
    return rows


def process_dir(d, force=False, check=False):
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
            pt, pair = decrypt_named(open(src, 'rb').read())
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


def archive_targets(dirs):
    """Capture directories under whatever was named (so a song dir works too)."""
    bases = dirs or [os.path.join(os.path.dirname(os.path.abspath(__file__)), 'extracted_charts')]
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


def run_archive(dirs, force=False, check=False):
    n_done = n_failed = 0
    for d in archive_targets(dirs):
        done, _skipped, failed = process_dir(d, force, check)
        if not (done or failed):
            continue
        print(f'{d}:')
        for x in done:
            print(f'  + {x}')
            n_done += 1
        for x in failed:
            print(f'  ! {x}')
            n_failed += 1
    print(f'\n{n_done} file(s) written, {n_failed} failure(s)'
          + (' (check only)' if check else ''))
    return 1 if n_failed else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('files', nargs='*', help='payload files (with --archive: capture directories)')
    ap.add_argument('--out', metavar='DIR', help='write results here instead of <file>.dec')
    ap.add_argument('--inspect', action='store_true', help='report only, write nothing')
    ap.add_argument('--keypair', choices=sorted(KEYPAIRS), help='force a static key pair')
    ap.add_argument('--archive', nargs='*', metavar='DIR',
                    help='decrypt every raw CDN capture under these trees '
                         '(default: all of extracted_charts/)')
    ap.add_argument('--force', action='store_true', help='with --archive: redo existing plaintext')
    ap.add_argument('--check', action='store_true', help='with --archive: report only, write nothing')
    args = ap.parse_args()

    if args.archive is not None:
        return run_archive(args.archive, force=args.force, check=args.check)

    if not args.files:
        ap.error('give one or more payload files, or --archive')

    for path in args.files:
        raw = open(path, 'rb').read()
        already = is_plaintext(raw)
        pair = ''
        if already:
            pt = raw
        else:
            try:
                if args.keypair:
                    pt, pair = decrypt(raw, args.keypair), args.keypair
                else:
                    pt, pair = decrypt_named(raw)
            except ValueError as e:
                print('%-46s %6d -> FAILED: %s' % (os.path.basename(path), len(raw), e))
                continue
        print('%-46s %s %6d -> %-9s %s'
              % (os.path.basename(path), 'PT ' if already else 'dec', len(raw),
                 pair or '-', summarize(pt)))
        if args.inspect:
            continue
        # only ever write a payload we could actually decode
        if not already and not plausible(pt):
            print('   !! refusing to write implausible plaintext')
            continue
        if args.out:
            os.makedirs(args.out, exist_ok=True)
            # keep the original extension so reference tooling accepts it
            dest = os.path.join(args.out, os.path.basename(path))
        else:
            dest = path + '.dec'
        if os.path.abspath(dest) == os.path.abspath(path):
            print('   !! refusing to overwrite the input file (use a different --out)')
            continue
        with open(dest, 'wb') as f:
            f.write(pt)


if __name__ == '__main__':
    sys.exit(main())
