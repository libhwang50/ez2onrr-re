#!/usr/bin/env python3
"""Administer server accounts / bearer tokens (the credential, see _auth.py).

    python server/_accounts.py issue --name Alice            # -> id + token
    python server/_accounts.py issue --name Bob --steamid 7656119...
    python server/_accounts.py list
    python server/_accounts.py ban   <id>
    python server/_accounts.py unban <id>

The token is shown **once** — only its SHA-256 is stored.  Give it to the client
(relay header `X-EZ2-Token`, or the single-machine `data/client_token.txt`).
The public id is the account's SteamID (a real one if `--steamid`, else a
generated pseudo id the Goldberg launcher should configure).
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _auth   # noqa: E402
import _store  # noqa: E402

DB = os.path.join(HERE, 'data', 'store.db')


def _store_obj():
    return _store.Store(DB)


def cmd_issue(a):
    st = _store_obj()
    token = _auth.new_token()
    acc = st.issue_account(_auth.hash_token(token), provider=a.provider,
                           provider_id=a.provider_id or a.name or '',
                           display_name=a.name or '', steamid=a.steamid)
    print(f'account id : {acc["id"]}')
    print(f'provider   : {acc["provider"]} / {acc["provider_id"]}')
    print(f'token      : {token}')
    print('(store this token client-side; it cannot be shown again)')


def cmd_list(a):
    st = _store_obj()
    rows = st.accounts()
    if not rows:
        print('(no accounts)')
        return
    print(f'{"id":<20} {"provider":<9} {"name":<20} {"banned":<6} last_seen')
    for r in rows:
        ts = r['last_seen']
        import time
        when = time.strftime('%Y-%m-%d %H:%M', time.localtime(ts)) if ts else '-'
        print(f'{r["id"]:<20} {r["provider"] or "-":<9} '
              f'{(r["display_name"] or "-"):<20} '
              f'{"yes" if r["banned"] else "no":<6} {when}')


def cmd_ban(a, banned):
    st = _store_obj()
    if st.account(a.id) is None:
        print(f'no such account: {a.id}', file=sys.stderr)
        return 1
    st.update_account(a.id, banned=1 if banned else 0)
    print(f'{a.id} {"banned" if banned else "unbanned"}')


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('issue', help='create an account + token')
    p.add_argument('--name', default='', help='display name')
    p.add_argument('--steamid', default=None,
                   help='public id (real SteamID); omit for a generated pseudo id')
    p.add_argument('--provider', default='admin')
    p.add_argument('--provider-id', default='')
    p.set_defaults(fn=cmd_issue)

    p = sub.add_parser('list', help='list accounts')
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser('ban', help='ban an account')
    p.add_argument('id')
    p.set_defaults(fn=lambda a: cmd_ban(a, True))

    p = sub.add_parser('unban', help='unban an account')
    p.add_argument('id')
    p.set_defaults(fn=lambda a: cmd_ban(a, False))

    args = ap.parse_args()
    return args.fn(args) or 0


if __name__ == '__main__':
    raise SystemExit(main())
