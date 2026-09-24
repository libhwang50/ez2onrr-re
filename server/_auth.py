"""Identity & access policy for the private server.

The **SteamID is not a credential** here.  A third party cannot verify a Steam
auth session ticket (the Web API's `AuthenticateUserTicket` / `CheckAppOwnership`
require the *app publisher's* key), and our RSA pubkey-swap only proves that a
client runs our patcher — not who it is.  So access is decided by a
**server-issued bearer token** (the `accounts` table in `_store.py`), and the
SteamID-shaped value is merely the public id an account appears under.

Providers are **optional**.  `python server/_accounts.py issue` mints tokens with
no external service; Discord (or any future OAuth provider) is just a
registration front end that calls `register_provider()`.

Config: `server/data/auth.json` (defaults below; git-ignored, personal).

    mode          "open"  — no token needed; the claimed SteamID is the account
                            (the old single/LAN behaviour, backwards compatible)
                  "token" — a valid token is required for a persistent account
    guest         "allow" — a missing/invalid token may still play (see below)
                  "deny"  — a missing/invalid token is refused at login
    guest_persist false   — guests get a throwaway profile, no leaderboard row
                  true    — guests are written to the store like accounts
    token_file    ""      — read the token from this local file when no
                            X-EZ2-Token header is present (single-machine use;
                            the public relay supplies the header instead)
    discord       {…}     — optional OAuth registration provider

The account id (the public id) is chosen at registration: a real SteamID for a
verified Steam account, else a generated pseudo-SteamID.  On the Goldberg path
the launcher writes that id into the emulator's config, so the client presents
exactly the id the server assigned.
"""
import hashlib
import json
import os
import secrets
import threading
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get('EZ2_DATA') or os.path.join(HERE, 'data')
CONFIG = os.path.join(DATA, 'auth.json')

DEFAULTS = {
    'mode': 'open',            # "open" | "token"
    'guest': 'allow',          # "allow" | "deny"
    'guest_persist': False,
    'token_file': '',
    'discord': {
        'enabled': False,
        'client_id': '',
        'client_secret': '',
        'guild_id': '',
        'redirect_uri': '',
    },
}

_lock = threading.RLock()
_cfg = None
_mtime = None


def load(force=False):
    """Current config, re-read when data/auth.json changes (like profile.json)."""
    global _cfg, _mtime
    with _lock:
        try:
            m = os.stat(CONFIG).st_mtime
        except OSError:
            m = None
        if _cfg is None or force or m != _mtime:
            base = json.loads(json.dumps(DEFAULTS))
            if m is not None:
                try:
                    with open(CONFIG) as f:
                        disk = json.load(f)
                    for k, v in disk.items():
                        if k == 'discord' and isinstance(v, dict):
                            base['discord'].update(v)
                        else:
                            base[k] = v
                except Exception:
                    pass
            _cfg, _mtime = base, m
        return _cfg


def new_token():
    """A 256-bit URL-safe bearer token (the client stores this, the server hashes)."""
    return secrets.token_urlsafe(32)


def hash_token(token):
    return hashlib.sha256((token or '').encode()).hexdigest()


class Identity:
    """The resolved caller: which account, and whether it may persist anything."""

    __slots__ = ('account_id', 'kind', 'persist', 'token', 'reason')

    def __init__(self, account_id, kind, persist, token=None, reason=''):
        self.account_id = account_id      # str public id, or None
        self.kind = kind                  # 'open' | 'account' | 'guest' | 'denied' | 'banned'
        self.persist = persist            # may write to the store / leaderboards
        self.token = token
        self.reason = reason

    def __repr__(self):
        return f'<Identity {self.kind} id={self.account_id} persist={self.persist}>'


def identify(store, claimed_steamid, token):
    """Resolve a login to an Identity.  Never raises.

    `claimed_steamid` is the (untrusted) SteamID from the RSA login JSON;
    `token` is from the relay header / token file / query, or None.
    """
    cfg = load()
    claimed = str(claimed_steamid) if claimed_steamid else None
    if cfg.get('mode') != 'token':
        # backwards-compatible open mode: the claimed SteamID is the account
        return Identity(claimed, 'open', True, token)
    if token:
        acc = store.account_by_token_hash(hash_token(token))
        if acc is not None:
            if int(acc.get('banned') or 0):
                return Identity(acc['id'], 'banned', False, token,
                                'this account is banned')
            store.touch_account(acc['id'])
            return Identity(acc['id'], 'account', True, token)
    if cfg.get('guest') == 'allow':
        return Identity(claimed, 'guest', bool(cfg.get('guest_persist')), token)
    return Identity(None, 'denied', False, token, 'a server account is required')


def register_provider(store, provider, provider_id, display_name=''):
    """Get-or-create the account behind an external identity (Discord user id…).

    Returns `(account, token_or_None)`; the token is returned only on creation,
    because only its hash is stored.
    """
    acc = store.account_by_provider(provider, provider_id)
    if acc:
        return acc, None
    token = new_token()
    acc = store.issue_account(hash_token(token), provider=provider,
                              provider_id=str(provider_id),
                              display_name=display_name)
    return acc, token


# ---------------- optional Discord OAuth (registration only) --------------

def discord_authorize_url(state=''):
    d = load().get('discord', {})
    if not d.get('enabled') or not d.get('client_id'):
        return None
    q = {
        'client_id': d['client_id'],
        'redirect_uri': d.get('redirect_uri', ''),
        'response_type': 'code',
        'scope': 'identify',
        'state': state,
    }
    if d.get('guild_id'):
        q['guild_id'] = d['guild_id']
        q['scope'] = 'identify guilds.join'
    return 'https://discord.com/oauth2/authorize?' + urllib.parse.urlencode(q)


def discord_exchange(code):
    """Exchange an OAuth code -> (provider_id, display_name).  May raise."""
    d = load().get('discord', {})
    body = urllib.parse.urlencode({
        'client_id': d['client_id'], 'client_secret': d['client_secret'],
        'grant_type': 'authorization_code', 'code': code,
        'redirect_uri': d.get('redirect_uri', ''),
    }).encode()
    req = urllib.request.Request(
        'https://discord.com/api/oauth2/token', data=body,
        headers={'Content-Type': 'application/x-www-form-urlencoded'})
    with urllib.request.urlopen(req, timeout=10) as r:
        tok = json.load(r)['access_token']
    req = urllib.request.Request(
        'https://discord.com/api/users/@me',
        headers={'Authorization': f'Bearer {tok}'})
    with urllib.request.urlopen(req, timeout=10) as r:
        me = json.load(r)
    name = me.get('global_name') or me.get('username') or str(me['id'])
    return str(me['id']), name
