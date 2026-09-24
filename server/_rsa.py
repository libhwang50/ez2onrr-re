"""Server-side RSA for the Frida-free session-key hand-off.

Working hypothesis (§3.1, §7.6): `c2s_login.data` is one PKCS#1 v1.5
RSA block (256 B = 2048-bit) carrying the client's freshly generated session
key/IV, encrypted under the build's baked-in `zf.publicKey`.  We cannot decrypt
that without the matching private key — which we do not have.

So the private server generates *its own* 2048-bit keypair and the client is
made to encrypt to it (a drop-in patcher swaps the live `zf.publicKey` string,
see `client/`).  The server then:

    c2s_login.data  --RSA-decrypt(server_rsa_private.pem)-->  key||iv

and writes `session_key.json`, exactly the file `_pserver.py` already reads per
request.  No Frida, no official server, no per-session harvester.

The public half is published as the same `<RSAKeyValue>` XML .NET's
`RSACryptoServiceProvider.FromXmlString` consumes, so it is a drop-in replacement
for the string the client holds.
"""
import base64
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, 'server', 'data')
PRIV = os.path.join(DATA, 'server_rsa_private.pem')
PUB_XML = os.path.join(DATA, 'server_rsa_public.xml')

# The client pads with PKCS#1 v1.5 by default (RSACryptoServiceProvider.Encrypt
# with fOAEP=false); every common OAEP variant is tried as a fallback — the
# padding is not observable from the wire.  PKCS#1 v1.5 is **not** in this tuple
# because `cryptography`'s high-level decrypt is not a validity oracle for it
# (see `_strict_pkcs1v15`); it is handled by a raw, strict decode instead.
def _oaep(h):
    return padding.OAEP(mgf=padding.MGF1(h), algorithm=h, label=None)


_PADDINGS = (
    ('oaep-sha1', _oaep(hashes.SHA1())),
    ('oaep-sha256', _oaep(hashes.SHA256())),
    ('oaep-sha384', _oaep(hashes.SHA384())),
    ('oaep-sha512', _oaep(hashes.SHA512())),
)


def _gen():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def load_private():
    """Load the server keypair, generating and persisting one if absent."""
    if os.path.exists(PRIV):
        with open(PRIV, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    key = _gen()
    os.makedirs(DATA, exist_ok=True)
    with open(PRIV, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
    os.chmod(PRIV, 0o600)
    return key


def _b64be(x: int, nbytes: int) -> str:
    return base64.b64encode(x.to_bytes(nbytes, 'big')).decode()


def public_xml(key=None) -> str:
    """The `<RSAKeyValue>` XML string, in .NET's own field/compose order."""
    key = key or load_private()
    n = key.public_key().public_numbers()
    return (f'<RSAKeyValue><Modulus>{_b64be(n.n, 256)}</Modulus>'
            f'<Exponent>{_b64be(n.e, 3)}</Exponent></RSAKeyValue>')


def public_modulus_b64(key=None) -> str:
    """Just the 344-char base64 modulus — the substring the patcher rewrites."""
    return _b64be((key or load_private()).public_key().public_numbers().n, 256)


def ensure_public_xml():
    """Materialise the public XML to data/ for the patcher to read."""
    xml = public_xml()
    try:
        old = open(PUB_XML).read()
    except Exception:
        old = None
    if old != xml:
        os.makedirs(DATA, exist_ok=True)
        with open(PUB_XML, 'w') as f:
            f.write(xml)
    return xml


def _strict_pkcs1v15(blob: bytes):
    """Raw RSA decode + strict PKCS#1 v1.5 unpad, or None.

    Do **not** use `cryptography`'s `RSAPrivateKey.decrypt(..., PKCS1v15())` as a
    validity oracle.  As of cryptography 48 it strips at the first 0x00 without
    verifying the mandatory `00 02` prefix, so it "succeeds" on ~82% of random
    blocks (measured 2459/3000) — which made every earlier "login RSA decrypted"
    log line meaningless and hid the fact that the swap was often not active.
    Here the RSA operation runs on the private numbers directly and the block is
    checked by the letter of RFC 8017 §7.2.2.
    """
    key = load_private()
    nums = key.private_numbers()
    n = nums.public_numbers.n
    k = (n.bit_length() + 7) // 8
    if len(blob) != k:
        return None
    c = int.from_bytes(blob, 'big')
    if c >= n:
        return None
    em = pow(c, nums.d, n).to_bytes(k, 'big')
    if em[0] != 0 or em[1] != 2:
        return None
    i = em.find(b'\x00', 2)
    if i < 10:                       # >= 8 non-zero padding bytes (PS length)
        return None
    return em[i + 1:]


def decrypt(blob: bytes):
    """RSA-decrypt one login block -> (label, plaintext) or (None, None).

    PKCS#1 v1.5 first, strictly validated; then the OAEP variants (whose
    internal hash check `cryptography` *does* enforce, so they are genuine
    oracles).  Returns the first scheme whose unpad succeeds.
    """
    pt = _strict_pkcs1v15(blob)
    if pt is not None:
        return 'pkcs1v15', pt
    key = load_private()
    for label, pad in _PADDINGS:
        try:
            pt = key.decrypt(blob, pad)
        except Exception:
            continue
        return label, pt
    return None, None


def split_key_iv(pt: bytes):
    """Interpret the decrypted login payload as the session key/IV.

    **Confirmed live 2026-09-24** (server/re/_login_probe.py, with the patcher
    `version.dll` active): `c2s_login.data` is RSA of a 141-byte JSON

        {"steamid":"…","appid":"…","version":"2026.09.04.001",
         "key":"<32 uppercase hex>","iv":"<16 uppercase hex>"}

    and its `key`/`iv` match the memory harvester's independent read of the
    client's live `zf.aes_key`/`zf.aes_iv` byte-for-byte.  So the hand-off is
    *not* a bare `key||iv` blob — the earlier 48-byte reading was a hypothesis.
    The fixed-length fallbacks are kept for other builds.
    """
    try:
        d = json.loads(pt.decode('utf-8'))
        if isinstance(d, dict) and d.get('key') and d.get('iv'):
            k = str(d['key']).encode('ascii', 'replace')
            v = str(d['iv']).encode('ascii', 'replace')
            if len(k) == 32 and len(v) == 16:
                return k, v
    except Exception:
        pass
    if len(pt) == 48:
        return pt[:32], pt[32:48]
    if len(pt) == 32:
        return pt, None
    if len(pt) == 16:
        return None, pt
    return None, None


def login_steamid(pt: bytes):
    """The SteamID carried in the RSA login JSON, or None.

    The login block is also the only place the server can learn *whose*
    session key this is, so the multi-user server keys its session registry on
    it (rather than trusting the separate, unauthenticated `identity=` field).
    """
    try:
        d = json.loads(pt.decode('utf-8'))
        if isinstance(d, dict) and d.get('steamid'):
            return str(d['steamid'])
    except Exception:
        pass
    return None


def _main():
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'init':
        k = load_private()
        ensure_public_xml()
        print('private :', PRIV)
        print('public  :', PUB_XML)
        print('modulus :', public_modulus_b64(k))
        return
    if len(sys.argv) > 1 and sys.argv[1] == 'show':
        ensure_public_xml()
        print(public_xml())
        return
    if len(sys.argv) > 1 and sys.argv[1] == 'selftest':
        # guard the oracle: a valid encryption must round-trip, random blocks
        # must be rejected outright (the whole point of the strict decode).
        import os as _os
        from cryptography.hazmat.primitives.asymmetric import padding as _p
        priv = load_private()
        good = priv.public_key().encrypt(b'sessionkey-test-1234567890', _p.PKCS1v15())
        lbl, pt = decrypt(good)
        assert lbl == 'pkcs1v15' and pt == b'sessionkey-test-1234567890', (lbl, pt)
        false_pos = sum(1 for _ in range(5000) if _strict_pkcs1v15(_os.urandom(256)))
        print(f'roundtrip ok; strict random false-positives: {false_pos}/5000')
        assert false_pos == 0, 'PKCS#1 v1.5 oracle is not strict!'
        return
    if len(sys.argv) > 2 and sys.argv[1] == 'decrypt':
        blob = open(sys.argv[2], 'rb').read()
        label, pt = decrypt(blob)
        if pt is None:
            print('no padding scheme decrypted the block')
            return
        k, iv = split_key_iv(pt)
        print(f'{label}: {len(pt)} bytes')
        print('  key:', k.decode('ascii', 'replace') if k else None)
        print('  iv :', iv.decode('ascii', 'replace') if iv else None)
        print('  hex:', pt.hex())
        return
    print(__doc__)


if __name__ == '__main__':
    _main()
