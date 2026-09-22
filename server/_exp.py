#!/usr/bin/env python3
"""Control the private server's experiment knobs (server/data/*.txt).

These files are re-read by server/_pserver.py on every request, so changes
apply live — no mitmdump restart. Only `hybrid on/off` changes the set of
endpoints forwarded upstream, which is also read per request.

    python server/_exp.py                       # show current state
    python server/_exp.py hybrid on             # forward login+pattern upstream
    python server/_exp.py hybrid pattern        # forward only the pattern
    python server/_exp.py hybrid off            # pure private server
    python server/_exp.py urls now              # Expires = now+150s (offline mint)
    python server/_exp.py urls skew             # Expires +1s (breaks signature only)
    python server/_exp.py urls future           # Expires +10y (breaks signature)
    python server/_exp.py urls expire           # Expires in the past
    python server/_exp.py urls noparams         # strip the query
    python server/_exp.py urls host             # swap the CDN host
    python server/_exp.py bck harvested         # the bCK from the last official response
    python server/_exp.py bck garbage           # 48 random bytes
    python server/_exp.py bck stale             # the older captured real key
    python server/_exp.py bck empty
    python server/_exp.py off                   # clear the url/bck mutations
    python server/_exp.py hybrid off            # back to a pure private server
    python server/_exp.py reset                 # clear everything

Hybrid mode is what makes a forwarded pattern response valid: the upstream
official server must have a live session, so `login` must be forwarded too.
Scores/records stay private either way unless you forward those endpoints.
"""
import os
import sys

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
KNOBS = {
    'endpoints': 'passthrough_endpoints.txt',
    'urls': 'mutate_urls.txt',
    'bck': 'mutate_bck.txt',
}
URL_MODES = ('now', 'skew', 'future', 'expire', 'noparams', 'host')
BCK_MODES = ('harvested', 'stale', 'garbage', 'empty')


def path(name):
    return os.path.join(DATA, KNOBS[name])


def get(name):
    try:
        return open(path(name)).read().strip()
    except Exception:
        return ''


def set_(name, value):
    if value:
        os.makedirs(DATA, exist_ok=True)
        open(path(name), 'w').write(value + '\n')
    elif os.path.exists(path(name)):
        os.remove(path(name))


def show():
    print(f'data dir: {DATA}')
    for name in KNOBS:
        v = get(name)
        print(f'  {name:10s} = {v!r}' + ('' if v else '   (off)'))
    legacy = os.path.exists(os.path.join(DATA, 'passthrough_pattern'))
    print(f'  legacy passthrough_pattern marker: {"present" if legacy else "absent"}'
          + ('  (use `hybrid pattern` instead)' if legacy else ''))


def main():
    a = sys.argv[1:]
    if not a:
        show()
        return 0
    if a[0] in ('off', 'reset'):
        # `off` = mutations only. Clearing the endpoints too was a trap: it
        # silently turned a hybrid response test back into a replay test.
        names = list(KNOBS) if a[0] == 'reset' else ['urls', 'bck']
        for name in names:
            set_(name, '')
        if a[0] == 'reset':
            legacy = os.path.join(DATA, 'passthrough_pattern')
            if os.path.exists(legacy):
                os.remove(legacy)
        show()
        return 0
    if len(a) != 2:
        print(__doc__)
        return 2
    what, val = a
    if what == 'hybrid':
        val = {'on': 'login,pattern', 'both': 'login,pattern',
               'login': 'login', 'pattern': 'c2s_get_pattern_file'}.get(val, val)
        set_('endpoints', '' if val in ('off', 'none') else val)
        legacy = os.path.join(DATA, 'passthrough_pattern')
        if os.path.exists(legacy):
            os.remove(legacy)
            print('removed legacy passthrough_pattern marker')
    elif what == 'urls':
        if val not in URL_MODES + ('off', 'none'):
            print(f'urls must be one of {URL_MODES} or off')
            return 2
        set_('urls', '' if val in ('off', 'none') else val)
    elif what == 'bck':
        if val not in BCK_MODES + ('off', 'none') and not val.startswith('literal:'):
            print(f'bck must be one of {BCK_MODES}, literal:<b64>, or off')
            return 2
        set_('bck', '' if val in ('off', 'none') else val)
    else:
        print(__doc__)
        return 2
    show()
    return 0


if __name__ == '__main__':
    sys.exit(main())
