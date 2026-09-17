#!/usr/bin/env python3
"""Parse EZ2ON REBOOT: R chart data — the `.ez` note chart and the `.ezi` keysound index.

REBOOT: R reuses the EZ2AC arcade container unchanged (see AGENTS.md 3.5), so this is an
EZ2AC `.ez` v7/v8 reader with the REBOOT specifics handled:

  * `.ez` plaintext is PKCS7-padded (trailing bytes are ignored, not parsed);
  * tracks are named by the arcade `TrackSlot` table for indices 0-21;
  * note records are 13 bytes (v7/v8).

Encrypted CDN payloads are accepted directly — they are decrypted first, so a captured
`cdn_ez_*.bin` can be handed straight to this tool.

Usage
-----
    python3 parse_chart.py <file.ez|file.ezi|cdn_*.bin>
    python3 parse_chart.py --json out.json <file.ez>
    python3 parse_chart.py --notes <file.ez>          # per-note listing
    python3 parse_chart.py --ezi <file.ezi>           # keysound listing
    python3 parse_chart.py --dir extracted_charts     # every chart in a tree

Verified vs. inferred
---------------------
Verified against the game's own parsed state and the file itself: the header fields, the
track walk, the 13-byte stride, the type-1 keysound index (every one lands inside the
`.ezi` index set), and two things confirmed against `normalLanes` over 3 songs x 4 lanes:

  * **tracks 3-6 are the 4K lanes, in order** (lane 0-3); and
  * **a type-1 note is a long note iff `flags not in (0, 6)`** — normal + long per lane
    reproduced `normalLanes` exactly on all 12 lanes.

The `velocity`/`pan` byte positions follow the EZ2AC spec, but `velocity` is 127 for
essentially every note here, so its meaning is untested. The unit of the `flags` value
on a long note is unknown (it is *not* a tick count). Tracks other than 3-6 are not
understood at all.
"""
import argparse
import json
import os
import struct
import sys

BYTES_PER_NOTE = 13
NOTE_TYPE_NAMES = {1: 'note', 2: 'volume', 3: 'bpm', 4: 'beats'}

# Arcade track roles (EZ2AC v6+). REBOOT files use 64 tracks; roles past 21 are not
# confirmed, so those are reported by index only.
TRACK_SLOTS = [
    'Control', 'BG L', 'BG R',
    '1P Key1', '1P Key2', '1P Key3', '1P Key4', '1P Key5',
    'Effector1', 'Effector2', '1P Scratch', '1P Pedal',
    'Effector3', 'Effector4',
    '2P Key1', '2P Key2', '2P Key3', '2P Key4', '2P Key5',
    '2P Scratch', '2P Pedal', 'Lights',
]


def track_role(i):
    return TRACK_SLOTS[i] if i < len(TRACK_SLOTS) else 'track%d' % i


# --------------------------------------------------------------------------- #
# .ezi — keysound index (plain text)
# --------------------------------------------------------------------------- #

class Instrument:
    __slots__ = ('index', 'velocity', 'filename')

    def __init__(self, index, velocity, filename):
        self.index = index
        self.velocity = velocity
        self.filename = filename

    def as_dict(self):
        return {'index': self.index, 'velocity': self.velocity, 'filename': self.filename}


def parse_ezi(data):
    """Parse a `.ezi` keysound index. Lines are `[index] [velocity] [filename]`."""
    if isinstance(data, str):
        data = open(data, 'rb').read()
    out = []
    for line in data.split(b'\n'):
        line = line.rstrip(b'\r').strip()
        if not line or line[0] == 0x06:      # skip PKCS7 padding
            continue
        parts = line.split(b' ')
        if len(parts) < 3:
            continue
        try:
            idx = int(parts[0])
            vel = int(parts[1])
        except ValueError:
            continue
        out.append(Instrument(idx, vel, parts[2].decode('latin-1')))
    return out


# --------------------------------------------------------------------------- #
# .ez — note chart
# --------------------------------------------------------------------------- #

class Note:
    __slots__ = ('position', 'type', 'params')

    def __init__(self, position, type_, params):
        self.position = position
        self.type = type_
        self.params = params

    @property
    def keysound(self):
        """Type-1 only: the .ezi keysound index (uint16)."""
        return struct.unpack_from('<H', self.params, 0)[0]

    @property
    def velocity(self):
        return self.params[2]

    @property
    def pan(self):
        return self.params[3]

    @property
    def flags(self):
        """uint16 at params[5:7]. 0 or 6 => normal note; anything else => long note."""
        return struct.unpack_from('<H', self.params, 5)[0]

    @property
    def is_long(self):
        """Type-1 only. Verified against the game's `normalLanes` on 3 songs x 4 lanes."""
        return self.type == 1 and self.flags not in (0, 6)

    @property
    def value(self):
        """Type-3 (BPM, float) / type-2 (volume) / type-4 (beats per measure)."""
        if self.type == 3:
            return struct.unpack_from('<f', self.params, 0)[0]
        return self.params[0]

    def as_dict(self):
        d = {'position': self.position, 'type': self.type,
             'typeName': NOTE_TYPE_NAMES.get(self.type, 'type%d' % self.type)}
        if self.type == 1:
            d.update(keysound=self.keysound, velocity=self.velocity,
                     pan=self.pan, flags=self.flags, long=self.is_long)
        else:
            d['value'] = self.value
        return d


class Track:
    __slots__ = ('index', 'name', 'num_ticks', 'data_size', 'notes')

    def __init__(self, index, name, num_ticks, data_size, notes):
        self.index = index
        self.name = name
        self.num_ticks = num_ticks
        self.data_size = data_size
        self.notes = notes

    @property
    def role(self):
        return self.name or track_role(self.index)

    def notes_of_type(self, t):
        return [n for n in self.notes if n.type == t]

    def as_dict(self):
        return {'index': self.index, 'role': self.role, 'rawName': self.name,
                'numTicks': self.num_ticks, 'dataSize': self.data_size,
                'notes': [n.as_dict() for n in self.notes]}


class Chart:
    def __init__(self, header, tracks, trailing=0):
        self.header = header
        self.tracks = tracks
        self.trailing = trailing

    @property
    def measure_count(self):
        tpm = self.header['ticksPerMeasure']
        return self.header['totalTicks'] / tpm if tpm else 0.0

    def as_dict(self):
        return {'header': self.header,
                'tracks': [t.as_dict() for t in self.tracks]}


def parse_ez(data):
    """Parse a decrypted `.ez`. Raises ValueError if it is not an EZFF container."""
    if isinstance(data, str):
        data = open(data, 'rb').read()
    if data[:4] != b'EZFF':
        raise ValueError('not an EZFF container (head %s)' % data[:4].hex())

    header = {
        'magic': 'EZFF',
        'version': data[5],
        'name': data[6:0x46].split(b'\0')[0].decode('latin-1', 'replace'),
        'ticksPerMeasure': struct.unpack_from('<H', data, 0x86)[0],
        'initialBPM': struct.unpack_from('<f', data, 0x88)[0],
        'trackCount': struct.unpack_from('<H', data, 0x8C)[0],
        'totalTicks': struct.unpack_from('<I', data, 0x8E)[0],
        'secondBPM': struct.unpack_from('<f', data, 0x92)[0],
    }

    tracks = []
    pos = 0x96
    for i in range(header['trackCount']):
        if data[pos:pos + 4] != b'EZTR':
            raise ValueError('track %d: expected EZTR at %#x, found %s'
                             % (i, pos, data[pos:pos + 4].hex()))
        name = data[pos + 6:pos + 0x46].split(b'\0')[0].decode('latin-1', 'replace')
        num_ticks, data_size = struct.unpack_from('<II', data, pos + 0x46)
        blob = data[pos + 0x4E:pos + 0x4E + data_size]
        notes = []
        for k in range(0, data_size - data_size % BYTES_PER_NOTE, BYTES_PER_NOTE):
            notes.append(Note(struct.unpack_from('<I', blob, k)[0], blob[k + 4],
                              blob[k + 5:k + BYTES_PER_NOTE]))
        tracks.append(Track(i, name, num_ticks, data_size, notes))
        pos += 0x4E + data_size

    return Chart(header, tracks, trailing=len(data) - pos)


# --------------------------------------------------------------------------- #
# loading (auto-decrypt)
# --------------------------------------------------------------------------- #

def load(path):
    """Read `path`; decrypt it if it is still an encrypted CDN payload.

    Returns (bytes, was_encrypted).
    """
    raw = open(path, 'rb').read()
    if raw[:5] == b'<?xml':
        raise ValueError('payload is a CDN XML error body (signed URL expired)')
    if raw[:4] == b'EZFF' or raw[:1].isdigit():
        return raw, False
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from decrypt_chart import decrypt
    try:
        return decrypt(raw), True
    except Exception as e:
        raise ValueError('not an EZFF chart, nor a decryptable CDN payload (%s)' % e)


# --------------------------------------------------------------------------- #
# reporting
# --------------------------------------------------------------------------- #

def summarize_chart(ch):
    h = ch.header
    lines = ['EZFF chart  v%d  name=%r' % (h['version'], h['name']),
             '  ticks/measure : %d' % h['ticksPerMeasure'],
             '  initial BPM   : %.3f' % h['initialBPM'],
             '  second BPM    : %.3f' % h['secondBPM'],
             '  total ticks   : %d  (%.2f measures)'
             % (h['totalTicks'], ch.measure_count),
             '  tracks        : %d' % h['trackCount']]
    total = sum(len(t.notes) for t in ch.tracks)
    lines.append('  note events   : %d' % total)
    if ch.trailing:
        lines.append('  trailing bytes: %d (PKCS7 padding)' % ch.trailing)

    types = {}
    for t in ch.tracks:
        for n in t.notes:
            types[n.type] = types.get(n.type, 0) + 1
    lines.append('  by type       : ' + ', '.join(
        '%s=%d' % (NOTE_TYPE_NAMES.get(k, 'type%d' % k), v)
        for k, v in sorted(types.items())))

    lines.append('  tracks carrying notes:')
    for t in ch.tracks:
        if not t.notes:
            continue
        n1 = t.notes_of_type(1)
        nlong = sum(1 for n in n1 if n.is_long)
        lane = ' lane%d' % (t.index - 3) if 3 <= t.index <= 6 else ''
        lines.append('    %-4d %-11s%s events=%-5d notes=%-5d (normal=%-5d long=%-4d) ticks=%d'
                     % (t.index, t.role, lane, len(t.notes), len(n1), len(n1) - nlong,
                        nlong, t.num_ticks))
    return '\n'.join(lines)


def note_lines(ch, instruments=None):
    names = {i.index: i.filename for i in (instruments or [])}
    tpm = ch.header['ticksPerMeasure'] or 1
    yield '# track  role        pos(ticks)  measure  keysound  vel  kind  filename'
    for t in ch.tracks:
        lane = 'lane%d' % (t.index - 3) if 3 <= t.index <= 6 else '-'
        for n in t.notes_of_type(1):
            yield '%-8d %-11s %10d %8.3f %9d %4d  %-4s  %s' % (
                t.index, lane, n.position, n.position / tpm,
                n.keysound, n.velocity, 'long' if n.is_long else 'n',
                names.get(n.keysound, ''))


def collect(dirpath):
    """Every plausible chart payload under dirpath: .ez/.ezi and cdn_*.bin captures."""
    found = []
    for root, _dirs, files in os.walk(dirpath):
        for fn in sorted(files):
            low = fn.lower()
            if low.endswith(('.ez', '.ezi')) or (low.startswith('cdn_') and low.endswith('.bin')):
                found.append(os.path.join(root, fn))
    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('paths', nargs='*', help='chart/index files, or a single file')
    ap.add_argument('--dir', metavar='DIR', action='append', default=[],
                    help='recurse a directory for .ez/.ezi/cdn_*.bin (repeatable)')
    ap.add_argument('--json', metavar='FILE', help='write the parse as JSON')
    ap.add_argument('--notes', action='store_true', help='print a per-note listing')
    ap.add_argument('--ezi', metavar='FILE', help='.ezi to join note listings against')
    args = ap.parse_args()

    files = list(args.paths)
    for d in args.dir:
        files.extend(collect(d))
    if not files:
        ap.error('no input files (give a path or --dir)')

    bulk = len(files) > 1
    if bulk:
        print('# %d file(s)' % len(files))
    results = {}

    for path in files:
        if bulk:
            print()
        try:
            data, decrypted = load(path)
        except (ValueError, OSError) as e:
            print('%-52s SKIP: %s' % (os.path.relpath(path), e))
            continue
        if decrypted:
            print('# decrypted in memory from an encrypted CDN payload', file=sys.stderr)

        rel = os.path.relpath(path)
        if path.lower().endswith('.ezi') or data[:4] != b'EZFF':
            insts = parse_ezi(data)
            if not insts:
                print('%-52s not a chart or keysound index' % rel)
                continue
            if bulk:
                print('%-52s ezi, %d keysounds' % (rel, len(insts)))
            else:
                print('ezi keysound index: %d entries, index range %d..%d'
                      % (len(insts), min(i.index for i in insts), max(i.index for i in insts)))
                for i in insts[:10]:
                    print('  %6d %2d  %s' % (i.index, i.velocity, i.filename))
                if len(insts) > 10:
                    print('  ...')
            results[rel] = [i.as_dict() for i in insts]
            continue

        ch = parse_ez(data)
        total = sum(len(t.notes) for t in ch.tracks)
        if bulk:
            print('%-52s %-10s v%d  %6.2f BPM  %5d events  %3d tracks'
                  % (rel, repr(ch.header['name']), ch.header['version'],
                     ch.header['initialBPM'], total, ch.header['trackCount']))
        if args.notes:
            insts = parse_ezi(load(args.ezi)[0]) if args.ezi else None
            for line in note_lines(ch, insts):
                print(line)
        elif not bulk:
            print(summarize_chart(ch))
        results[rel] = ch.as_dict()

    if args.json:
        payload = results
        if len(results) == 1 and not bulk:
            payload = next(iter(results.values()))
        json.dump(payload, open(args.json, 'w'), indent=1)
        print('# wrote %s' % args.json, file=sys.stderr)


if __name__ == '__main__':
    try:
        main()
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
