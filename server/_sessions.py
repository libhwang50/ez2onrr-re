"""Per-user API session registry (multi-user keying).

A single-client server kept the one live AES key/IV in a global file
(`server/session_key.json`).  Serving several clients at once needs a registry,
because every request must be decrypted with *its own* client's key and every
response encrypted with the same.

The key/IV (and the SteamID) arrive together, RSA-wrapped, in `c2s_login.data`
(see `server/_rsa.py`), so login is the only place a session is *created*:

    registry.bind(steamid, key, iv, addr)

The API requests that follow carry no SteamID, so `_pserver.resolve_session`
attributes them, in order:

  1. the address the client last used (fast path), else
  2. trial decryption against every known key — the `d3ad76d3adb8` magic plus
     PKCS#7 padding is a strong oracle and the key count is small.

That is transport-independent, so it survives NAT and a client that reconnects
on a new port, and it degrades correctly for the legacy single-client file
harvester (`_harvest_mem.py`).

Keys are ephemeral (the client regenerates them per session, and rotates them
within a launch), so the registry is in-memory only: a server restart simply
waits for the next login.  Entries are pruned by age.
"""
import threading
import time


class Session:
    """One client's live API key/IV, plus the identity that owns it."""

    __slots__ = ('steamid', 'key', 'iv', 'addr', 'seen', 'source', 'persist',
                 'kind')

    def __init__(self, steamid, key, iv, addr=None, source='rsa'):
        self.steamid = steamid            # str SteamID, or None for the legacy file
        self.key = key                    # 32 ASCII bytes (zf.aes_key)
        self.iv = iv                      # 16 ASCII bytes (zf.aes_iv)
        self.addr = addr                  # last source IP seen
        self.seen = time.time()
        self.source = source              # 'rsa' | 'file'
        self.persist = True               # False for a non-persistent guest
        self.kind = 'open'                # 'open' | 'account' | 'guest'

    def touch(self):
        self.seen = time.time()

    def age(self):
        return time.time() - self.seen

    def label(self):
        who = self.steamid or 'legacy'
        tail = self.key[-4:].decode('ascii', 'replace') if self.key else '????'
        return f'{who}/…{tail}'

    def __repr__(self):
        return f'<Session {self.label()} src={self.source}>'


class Registry:
    """Thread-safe steamid -> Session map, with an address cache."""

    def __init__(self):
        self._by_id = {}
        self._by_addr = {}
        self._lock = threading.RLock()

    # -- creation ---------------------------------------------------------
    def bind(self, steamid, key, iv, addr=None, source='rsa'):
        """Create or refresh the session for `steamid` and return it.

        A new login is authoritative (the key rotates within a launch), so the
        stored key/IV are replaced even if the id is already known.
        """
        steamid = str(steamid) if steamid is not None else None
        with self._lock:
            s = self._by_id.get(steamid)
            if s is None:
                s = Session(steamid, key, iv, addr, source)
                self._by_id[steamid] = s
            else:
                s.key, s.iv, s.source = key, iv, source
                s.touch()
            if addr:
                s.addr = addr
                self._by_addr[addr] = steamid
            return s

    def note_addr(self, addr, steamid):
        if addr and steamid is not None:
            with self._lock:
                self._by_addr[addr] = str(steamid)

    # -- lookup -----------------------------------------------------------
    def by_id(self, steamid):
        with self._lock:
            s = self._by_id.get(str(steamid) if steamid is not None else None)
            if s:
                s.touch()
            return s

    def by_addr(self, addr):
        if not addr:
            return None
        with self._lock:
            sid = self._by_addr.get(addr)
            s = self._by_id.get(sid) if sid is not None else None
            if s:
                s.touch()
            return s

    def all(self):
        """A snapshot list of live sessions (newest last)."""
        with self._lock:
            return sorted(self._by_id.values(), key=lambda s: s.seen)

    def __len__(self):
        with self._lock:
            return len(self._by_id)

    # -- housekeeping -----------------------------------------------------
    def prune(self, max_age=12 * 3600):
        with self._lock:
            dead = [sid for sid, s in self._by_id.items() if s.age() > max_age]
            for sid in dead:
                s = self._by_id.pop(sid)
                if s.addr and self._by_addr.get(s.addr) == sid:
                    del self._by_addr[s.addr]
            return len(dead)
