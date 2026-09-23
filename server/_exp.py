#!/usr/bin/env python3
"""Control the private server's experiment knobs (server/data/*.txt).

These files are re-read by server/_pserver.py on every request, so changes
apply live — no mitmdump restart. Only `hybrid on/off` changes the set of
endpoints forwarded upstream, which is also read per request.

    python server/_exp.py                       # show current state
    python server/_exp.py offline               # (the default) fully offline serving
    python server/_exp.py harvest               # capture: forward login+pattern+cdn, no mutations
    python server/_exp.py hybrid on             # forward login+pattern upstream
    python server/_exp.py hybrid pattern        # forward only the pattern
    python server/_exp.py hybrid off            # pure private server (also the default)
    python server/_exp.py urls now              # Expires = now+150s (offline mint; the default)
    python server/_exp.py urls skew             # Expires +1s (breaks signature only)
    python server/_exp.py urls future           # Expires +10y (breaks signature)
    python server/_exp.py urls expire           # Expires in the past
    python server/_exp.py urls noparams         # strip the query
    python server/_exp.py urls host             # swap the CDN host
    python server/_exp.py bck harvested         # the bCK from the last official response
    python server/_exp.py bck garbage           # 48 random bytes
    python server/_exp.py bck mint              # AES(live key, client constant) — the default
    python server/_exp.py bck mint:zero         # minted with a fixed payload
    python server/_exp.py bck stale             # the older captured real key
    python server/_exp.py bck empty
    python server/_exp.py chart any             # serve the song's chart for any variant (default)
    python server/_exp.py chart exact           # only exact keymode/difficulty (capturing)
    python server/_exp.py off                   # clear explicit mutations -> back to offline defaults
    python server/_exp.py hybrid off            # back to a pure private server
    python server/_exp.py reset                 # clear everything -> offline defaults

Offline is now the default. With no knob files the addon forwards nothing,
mints its own CDN `Expires` and `bundleCryptKey` from the client's live session
key, and serves a song's chart for any requested variant. `mutate_urls.txt` /
`mutate_bck.txt` therefore *override* that default; `off`/`none` turns a piece
of it off (a raw replay) for experiments.

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
    'chart': 'chart_mode.txt',
}
URL_MODES = ('now', 'skew', 'future', 'expire', 'noparams', 'host')
CHART_MODES = ('exact', 'any')
BCK_MODES = ('harvested', 'stale', 'garbage', 'empty', 'mint')


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
    print('  (fully offline is the default; explicit knob files override it)')
    for name in KNOBS:
        v = get(name)
        print(f'  {name:10s} = {v!r}' + ('' if v else '   (default)'))
    legacy = os.path.exists(os.path.join(DATA, 'passthrough_pattern'))
    print(f'  legacy passthrough_pattern marker: {"present" if legacy else "absent"}'
          + ('  (use `hybrid pattern` instead)' if legacy else ''))


def main():
    a = sys.argv[1:]
    if not a:
        show()
        return 0
    if a[0] == 'offline':
        # Fully offline: no endpoint is forwarded, we mint the URLs, and the
        # token is produced here from the client's payload constant + the live
        # session key (byte-identical to what the official server would send).
        set_('endpoints', '')
        set_('urls', 'now')
        set_('bck', 'mint')
        set_('chart', 'any')
        legacy = os.path.join(DATA, 'passthrough_pattern')
        if os.path.exists(legacy):
            os.remove(legacy)
        show()
        return 0
    if a[0] == 'harvest':
        # The capture mode: forward login+pattern so the upstream mints a real
        # session and real signed URLs, AND forward `cdn` so charts we do not
        # hold yet come from the official CDN and get filed into
        # extracted_charts/ (without `cdn` a missing chart is a local 404 and
        # nothing can ever be captured).
        set_('endpoints', 'login,pattern,cdn')
        # NO url/bck mutation here: the forwarded response carries real signed
        # CloudFront URLs and a fresh token, and CloudFront *checks the
        # signature* (the client never does) - rewriting Expires with our own
        # signature is a guaranteed 403. Offline mode is where we mint them.
        set_('urls', '')
        set_('bck', '')
        set_('chart', 'exact')     # irrelevant in passthrough; set for clarity
        show()
        return 0
    if a[0] in ('off', 'reset'):
        # `off` clears the explicit mutations, which now means "back to the
        # fully-offline defaults" (mint URLs + mint bCK + chart any). Use
        # `urls off` / `bck off` for a raw replay experiment. Clearing the
        # endpoints too was a trap: it silently turned a hybrid response test
        # back into a replay test.
        names = list(KNOBS) if a[0] == 'reset' else ['urls', 'bck', 'chart']
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
    elif what == 'chart':
        if val not in CHART_MODES + ('off', 'none'):
            print(f'chart must be one of {CHART_MODES} or off')
            return 2
        set_('chart', '' if val in ('off', 'none') else val)
    elif what == 'bck':
        if (val not in BCK_MODES + ('off', 'none')
                and not val.startswith(('literal:', 'mint:'))):
            print(f'bck must be one of {BCK_MODES}, mint:<payload>, literal:<b64>, or off')
            return 2
        set_('bck', '' if val in ('off', 'none') else val)
    else:
        print(__doc__)
        return 2
    show()
    return 0


if __name__ == '__main__':
    sys.exit(main())
