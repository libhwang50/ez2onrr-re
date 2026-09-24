#!/usr/bin/env python3
"""Key-discovery harness that cracked the EZ2ON CDN chart cipher.

This is the record of the hunt, kept because the negative space is informative: the
cipher turned out to be `mask ∘ AES-256-CBC/PKCS7` with a **static** key
(`InGameCore.svo`/`svp`), not a per-song key. The ~2.7 M-key sweep that failed had
searched `rjn`/`bundleCryptKey` derivations and — critically — tried AES directly on
the ciphertext, without the stage-1 mask, which no key can ever undo.

The canonical implementation now lives at `ripper/decrypt_chart.py`; this
module just imports it so there is exactly one copy of the algorithm.

Usage:
    python3 tools/crypto/_chart_cipher.py <ciphertext.ez>
    python3 tools/crypto/_chart_cipher.py --selftest
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, 'ripper'))

from decrypt_chart import (  # noqa: E402
    SVQ, SVR, SVO, SVP, _SBOX, mask_byte, unmask, decrypt, looks_like_ezi, summarize,
)

assert len(SVQ) == 64 and len(SVR) == 16 and len(SVO) == 32 and len(SVP) == 16


def selftest():
    print('svq   ', SVQ.hex())
    print('svr   ', SVR.hex())
    print('SBOX  ', _SBOX.hex())
    print('svo   ', SVO.hex(), '(AES key)')
    print('svp   ', SVP.hex(), '(AES IV)')
    print('mask[0]=%02x mask[1]=%02x mask[16]=%02x' % (mask_byte(0), mask_byte(1), mask_byte(16)))


def main():
    args = sys.argv[1:]
    if not args or args[0] == '--selftest':
        selftest()
        return
    for path in args:
        raw = open(path, 'rb').read()
        pt = raw if raw[:4] == b'EZFF' or raw[:5] == b'<?xml' or looks_like_ezi(raw) else decrypt(raw)
        print('%-46s %6d -> %s' % (os.path.basename(path), len(raw), summarize(pt)))


if __name__ == '__main__':
    main()
