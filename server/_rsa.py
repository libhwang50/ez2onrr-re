"""Server-side RSA for the Frida-free session-key hand-off.

Working hypothesis (AGENTS.md §3.1, §7.6): `c2s_login.data` is one PKCS#1 v1.5
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
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, 'server', 'data')
PRIV = os.path.join(DATA, 'server_rsa_private.pem')
PUB_XML = os.path.join(DATA, 'server_rsa_public.xml')

# the client pads with PKCS#1 v1.5 by default (RSACryptoServiceProvider.Encrypt
# with fOAEP=false); try it first, then every common OAEP variant — the
# padding is not observable from the wire, so accept any that unpads to a
# plausible key length.
def _oaep(h):
    return padding.OAEP(mgf=padding.MGF1(h), algorithm=h, label=None)


_PADDINGS = (
    ('pkcs1v15', padding.PKCS1v15()),
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


def decrypt(blob: bytes):
    """RSA-decrypt one login block -> (label, plaintext) or (None, None).

    Tries every padding scheme; returns the first that yields a plausible
    session key (len 16/32/48) — the alternative is an unpad failure.
    """
    key = load_private()
    for label, pad in _PADDINGS:
        try:
            pt = key.decrypt(blob, pad)
        except Exception:
            continue
        # accept ANY unpadding success: the payload layout is a hypothesis, so
        # a valid unpad of unexpected length still proves the client used our
        # key and is worth logging/reporting
        return label, pt
    return None, None


def split_key_iv(pt: bytes):
    """Interpret the decrypted login payload as the session key/IV.

    48 B = key(32) || iv(16) is the expected shape.  32 B = key only.  16 B is
    ambiguous; the login experiment records the raw bytes so the true layout can
    be pinned without guessing here.
    """
    if len(pt) == 48:
        return pt[:32], pt[32:48]
    if len(pt) == 32:
        return pt, None
    if len(pt) == 16:
        return None, pt
    return None, None


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
