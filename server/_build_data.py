#!/usr/bin/env python3
"""Build server/data/ for the private server from captured artefacts.

Inputs (already in the repo):
  mitm_parsed/c2s_login.bin, c2s_get_myinfo.bin, c2s_get_gameinfo.bin
      — Sep-16 API responses, base64 AES-CBC (session key of that session,
        hardcoded below — only used to READ them once, here).
  extracted_charts/*/*/*/ident.json + cdn_ez_*.bin / cdn_ezi_*.bin
      — per-variant chart captures with their real CDN URLs.
  mitm_parsed/replay_0922/body_013_resp.bin, body_014_resp.bin
      — the Sta-Finite 5K HD chart + ezi ciphertext from the Sep-22 session.
  mitm_parsed/pattern_keys.json + mitm_parsed/cdn_*.bin
      — Sep-16 pattern responses and their CDN bodies (path-only mapping).

Outputs (server/data/):
  login.json myinfo.json gameinfo.json   — decrypted response templates
  profile.json                           — member-field overrides (edit me)
  cdn_paths.json                         — CDN path -> local file
  charts.json                            — (song, keymode, levelmode) -> CDN paths
"""
import base64
import json
import os
import re
import shutil
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'server', 'data')
os.makedirs(OUT, exist_ok=True)

# Session key of the capture that produced the API templates — never committed.
# Export EZ2_API_SESSION_KEY / EZ2_API_SESSION_IV before running.
OLD_KEY = os.environ.get('EZ2_API_SESSION_KEY', '').encode()
OLD_IV = os.environ.get('EZ2_API_SESSION_IV', '').encode()


def dec_b64_file(path):
    s = ''.join(open(path, 'rb').read().decode().split())
    raw = base64.b64decode(s + '=' * (-len(s) % 4))
    return unpad(AES.new(OLD_KEY, AES.MODE_CBC, OLD_IV).decrypt(raw), 16)


def norm(s):
    return re.sub(r'[^a-z0-9]', '', (s or '').lower())


def main():
    # ---- API response templates ----
    login = json.loads(dec_b64_file(os.path.join(ROOT, 'mitm_parsed', 'c2s_login.bin')))
    myinfo = json.loads(dec_b64_file(os.path.join(ROOT, 'mitm_parsed', 'c2s_get_myinfo.bin')))
    gameinfo = json.loads(dec_b64_file(os.path.join(ROOT, 'mitm_parsed', 'c2s_get_gameinfo.bin')))
    json.dump(login, open(os.path.join(OUT, 'login.json'), 'w'), indent=1, ensure_ascii=False)
    json.dump(myinfo, open(os.path.join(OUT, 'myinfo.json'), 'w'), indent=1, ensure_ascii=False)
    json.dump(gameinfo, open(os.path.join(OUT, 'gameinfo.json'), 'w'), indent=1, ensure_ascii=False)
    print('login.json / myinfo.json / gameinfo.json written '
          f'(musicList={len(gameinfo.get("musicList", []))} entries)')

    # profile overrides — user-tunable; never clobber local edits
    profile = {
        "_comment": "Overrides merged into member/memberinfo before serving.",
        "NICKNAME": "your-nickname",
        "LEVEL": 98,
        "RATING": 0.0
    }
    ppath = os.path.join(OUT, 'profile.json')
    if not os.path.exists(ppath):
        json.dump(profile, open(ppath, 'w'), indent=1)
        print('profile.json written (placeholder — edit me)')
    else:
        print('profile.json kept (already exists)')

    # ---- CDN path -> local file ----
    cdn_paths = {}
    charts = []
    keymap = {'4k': 1, '5k': 2, '6k': 3, '8k': 4}   # API keymode (1-based)
    diffmap = {'ez': 1, 'nm': 2, 'hd': 3, 'shd': 4}

    def path_of(url):
        m = re.match(r'https://game1-cdn\.ez2game\.co\.kr(/[^?]+)', url or '')
        return m.group(1) if m else None

    def add_cdn(url, local_file):
        p = path_of(url)
        if p and local_file and os.path.exists(local_file):
            cdn_paths[p] = os.path.relpath(local_file, ROOT)
        return p

    # from extracted_charts/
    for dirpath, _dirs, files in os.walk(os.path.join(ROOT, 'extracted_charts')):
        if 'ident.json' not in files:
            continue
        ident = json.load(open(os.path.join(dirpath, 'ident.json')))
        ez_url, ezi_url = ident.get('ez_url'), ident.get('ezi_url')
        ez_f = next((f for f in files if f.startswith('cdn_ez_')), None)
        ezi_f = next((f for f in files if f.startswith('cdn_ezi_')), None)
        ez_p = add_cdn(ez_url, os.path.join(dirpath, ez_f) if ez_f else None)
        ezi_p = add_cdn(ezi_url, os.path.join(dirpath, ezi_f) if ezi_f else None)
        rel = os.path.relpath(dirpath, ROOT).split(os.sep)  # extracted_charts/<song>/<km>/<diff>
        if ez_p and ezi_p and len(rel) == 4 and rel[1] != '' and rel[2] in keymap:
            charts.append({
                'song': rel[1], 'song_norm': norm(rel[1]),
                'keymode': keymap[rel[2]], 'levelmode': diffmap[rel[3]],
                'keymode_dir': rel[2], 'levelmode_dir': rel[3],
                'ez_path': ez_p, 'ezi_path': ezi_p,
            })

    # the Sep-22 Sta-Finite 5K HD capture
    src = os.path.join(ROOT, 'mitm_parsed', 'replay_0922')
    if os.path.exists(os.path.join(src, 'body_013_resp.bin')):
        dst = os.path.join(OUT, 'cdn')
        os.makedirs(dst, exist_ok=True)
        a = os.path.join(dst, 'finite_5k_hd_ez.bin')
        b = os.path.join(dst, 'finite_5k_hd_ezi.bin')
        shutil.copy(os.path.join(src, 'body_013_resp.bin'), a)
        shutil.copy(os.path.join(src, 'body_014_resp.bin'), b)
        ez_p, ezi_p = '/fb_2/90/bc592cbb377a044591bda10c423cfe83be8a02e4c827e2a0af1a2cdf2fef74', \
                      '/fb_2/f8/96e8a91db9f67a001a53c5ee34808846ff10e197481cd346a8e901e14aa64e'
        cdn_paths[ez_p] = os.path.relpath(a, ROOT)
        cdn_paths[ezi_p] = os.path.relpath(b, ROOT)
        charts.append({'song': 'finite', 'song_norm': norm('finite'),
                       'keymode': 2, 'levelmode': 3, 'keymode_dir': '5k', 'levelmode_dir': 'hd',
                       'ez_path': ez_p, 'ezi_path': ezi_p})

    # Sep-16 mitm_parsed/cdn_*.bin — path-only entries (serving fallback)
    pk_path = os.path.join(ROOT, 'mitm_parsed', 'pattern_keys.json')
    if os.path.exists(pk_path):
        for rec in json.load(open(pk_path)):
            for urlkey in ('final_url_ez', 'final_url_ezi'):
                p = path_of(rec['json'].get(urlkey))
                if not p:
                    continue
                tail = p.strip('/').replace('/', '_')[-60:]
                cand = os.path.join(ROOT, 'mitm_parsed', f'cdn_{tail}.bin')
                if not os.path.exists(cand):
                    pref = p.split('/')[2][:2]  # fb_2/<xx>/<hash>
                    glob_name = f'cdn_*_{pref.split("/")[0]}_{p.split("/")[2][:2]}_{p.split("/")[3][:8]}'
                    hits = [f for f in os.listdir(os.path.join(ROOT, 'mitm_parsed'))
                            if f.startswith('cdn_') and p.split('/')[3][:8] in f]
                    cand = os.path.join(ROOT, 'mitm_parsed', hits[0]) if hits else None
                if cand and os.path.exists(cand):
                    cdn_paths[p] = os.path.relpath(cand, ROOT)

    # ---- real pattern responses from a keyed official capture (if present):
    #      served VERBATIM (real signed URLs + real bundleCryptKey) ----
    rp = os.path.join(ROOT, 'mitm_parsed', 'replay_official2', 'flows.jsonl')
    if os.path.exists(rp):
        sys.path.insert(0, ROOT)
        from Crypto.Cipher import AES as _AES
        from Crypto.Util.Padding import unpad as _unpad
        import base64 as _b64
        key = os.environ.get('EZ2_API_SESSION_KEY', '').encode()
        iv = os.environ.get('EZ2_API_SESSION_IV', '').encode()
        if key and iv:
            replays = {}
            for line in open(rp):
                rec = json.loads(line)
                if 'c2s_get_pattern_file' not in rec.get('path', ''):
                    continue
                try:
                    enc = rec['req_body_text'].split('data=', 1)[1].split('&')[0]
                    import urllib.parse as _up
                    raw = _b64.b64decode(_up.unquote(enc) + '=' * 3)
                    req = json.loads(_unpad(_AES.new(key, _AES.MODE_CBC, iv).decrypt(raw[6:]), 16))
                    resp = json.loads(_unpad(_AES.new(key, _AES.MODE_CBC, iv).decrypt(
                        _b64.b64decode(rec['resp_body_text'] + '=' * (-len(rec['resp_body_text']) % 4))), 16))
                    if resp.get('result') != 1:
                        continue
                    k = (norm(req.get('musicresourcename', '')),
                         int(req.get('keymode', 0)), int(req.get('levelmode', 0)))
                    replays[k] = resp
                except Exception:
                    continue
            json.dump(replays, open(os.path.join(OUT, 'pattern_replay.json'), 'w'), indent=1)
            print(f'pattern_replay.json: {len(replays)} real responses')

    json.dump(cdn_paths, open(os.path.join(OUT, 'cdn_paths.json'), 'w'), indent=1)
    json.dump(charts, open(os.path.join(OUT, 'charts.json'), 'w'), indent=1)
    print(f'cdn_paths.json: {len(cdn_paths)} paths')
    print(f'charts.json: {len(charts)} chart variants:')
    for c in charts:
        print(f"  {c['song']:14s} keymode={c['keymode']} levelmode={c['levelmode']}")

    # ---- real leaderboard CSVs from an official-server capture (if present) ----
    rp = os.path.join(ROOT, 'mitm_parsed', 'replay_official', 'flows.jsonl')
    if os.path.exists(rp):
        import urllib.parse
        seen = {}
        for line in open(rp):
            rec = json.loads(line)
            if 'game1-rank' not in rec['host'] or rec['status'] != 200:
                continue
            q = rec['path'].split('data=', 1)[1] if 'data=' in rec['path'] else ''
            q = urllib.parse.unquote(q)
            body = rec.get('resp_body_text')
            if not body or q.startswith('plf') or q == 'get_battle_server_ip':
                continue
            if q not in seen or len(seen[q]) < len(body):
                seen[q] = body
        os.makedirs(os.path.join(OUT, 'rank_csv'), exist_ok=True)
        for q, body in seen.items():
            fn = 'rank_csv/' + q.replace(',', '_').replace('/', '') + '.csv'
            open(os.path.join(OUT, fn), 'w').write(body)
        print(f'rank_csv/: {len(seen)} real leaderboard responses')


if __name__ == '__main__':
    sys.exit(main())
