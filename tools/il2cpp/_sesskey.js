// Session-key reader + error-site hunter. Read-only.
//
// readkey: zf.aes_key / zf.aes_iv statics (the API session key).
// hunt(korean): locate a Korean error-message string literal in the mapped
// metadata (which lives ADJACENT to the module, beyond SizeOfImage), find the
// literal THUNK serving it (ecx=index, edx=data-offset, r8d=length before the
// shared helper call), dump neighbouring literals, and attribute the code that
// calls that thunk. All inside the ONE session this script runs in - extra
// Frida sessions crash the game.

rpc.exports.readkey = function () {
  return Il2Cpp.perform(() => {
    const zf = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("zf");
    const read = (name) => {
      try {
        const v = zf.field(name).value;
        if (v === null || v === undefined) return null;
        let s; try { s = v.content; } catch (e) { s = undefined; }
        if (typeof s !== 'string') s = String(v);
        return s;
      } catch (e) { return 'ERR: ' + e; }
    };
    return JSON.stringify({ aes_key: read("aes_key"), aes_iv: read("aes_iv") });
  });
};

function utf16hex(s) {
  let h = '';
  for (const ch of s) {
    const c = ch.charCodeAt(0);
    h += (c & 0xff).toString(16).padStart(2, '0') + ((c >> 8) & 0xff).toString(16).padStart(2, '0');
  }
  return h;
}

// known thunk RVAs for this client build (base 0x6ffff23c0000 references):
//   aes_key thunk 0xE2A5F0, aes_iv thunk 0xE2A690
const AESKEY_THUNK_RVA = 0xe2a5f0;
const AESIV_THUNK_RVA = 0xe2a690;
const DEFAULT_KEY = '01234567890123456789012345678901';
const DEFAULT_IV = '0123456789012345';

function parseThunk(va) {
  const b = new Uint8Array(va.readByteArray(0x40));
  let idx = null, off = null, len = null, callRel = null, callOff = null;
  for (let i = 0; i + 5 <= b.length; i++) {
    if (b[i] === 0xb9) idx = (b[i+1] | (b[i+2] << 8) | (b[i+3] << 16) | ((b[i+4] << 24) >>> 0)) >>> 0;
    if (b[i] === 0xba) off = (b[i+1] | (b[i+2] << 8) | (b[i+3] << 16) | ((b[i+4] << 24) >>> 0)) >>> 0;
    if (b[i] === 0x41 && b[i+1] === 0xb8) len = (b[i+2] | (b[i+3] << 8) | (b[i+4] << 16) | ((b[i+5] << 24) >>> 0)) >>> 0;
    if (b[i] === 0x45 && b[i+1] === 0x31 && b[i+2] === 0xc0) len = 0;
    if (b[i] === 0xe8) { callRel = b[i+1] | (b[i+2] << 8) | (b[i+3] << 16) | (b[i+4] << 24); callOff = i; break; }
  }
  return { idx, off, len, helper: callOff === null ? null : va.add(callOff + 5 + callRel) };
}

rpc.exports.hunt = function (korean) {
  return Il2Cpp.perform(() => {
    const out = {};
    const mod = Process.getModuleByName('GameAssembly.dll');
    const base = mod.base;
    out.base = base.toString(16);

    // known literal-region addresses for the Korean message (previous session,
    // identical module base); verify each by reading the text
    const candidates = ['0x6ffff96ba736', '0x6fffffd70018', '0x6fffffd75cfa'];
    const windows = [];
    for (const c of candidates) {
      try {
        const t = ptr(c).readUtf16String(40);
        windows.push({ addr: c, verify: t ? t.slice(0, 40) : null });
      } catch (e) { windows.push({ addr: c, err: '' + e }); }
    }
    out.candidates = windows;

    // dump a decoded window around every candidate that verifies
    out.koreanWindows = [];
    for (const c of candidates) {
      const a = ptr(c);
      let range = null;
      for (const r of Process.enumerateRanges({ protection: 'r--', coalesce: true })
          .concat(Process.enumerateRanges({ protection: 'rw-', coalesce: true }))) {
        if (a.compare(r.base) >= 0 && a.compare(r.base.add(r.size)) < 0) { range = r; break; }
      }
      if (!range) { out.koreanWindows.push({ addr: c, err: 'no containing range' }); continue; }
      let s0 = a.sub(0x500); if (s0.compare(range.base) < 0) s0 = range.base;
      let e0 = a.add(0x700); const re = range.base.add(range.size);
      if (e0.compare(re) > 0) e0 = re;
      try {
        const u = new Uint8Array(s0.readByteArray(e0.sub(s0).toInt32()));
        let txt = '', hex = '';
        for (let i = 0; i + 1 < u.length; i += 2) {
          const ch = u[i] | (u[i+1] << 8);
          txt += (ch >= 32 && ch !== 0xfffe) ? String.fromCharCode(ch) : '\u00b7';
        }
        for (let i = 0; i < u.length; i++) hex += u[i].toString(16).padStart(2, '0');
        out.koreanWindows.push({ addr: c, start: s0.toString(16), text: txt, hex: hex });
      } catch (e) { out.koreanWindows.push({ addr: c, err: '' + e }); }
    }
    return JSON.stringify(out);
  });
};

// heavy: enumerate every string-literal thunk (call sites of the literal
// helper, RVA 0xC12390) - run only when needed
rpc.exports.thunks = function () {
  return Il2Cpp.perform(() => {
    const mod = Process.getModuleByName('GameAssembly.dll');
    const base = mod.base, size = mod.size;
    const helper = base.add(0xc12390);
    const xranges = Process.enumerateRanges({ protection: 'x', coalesce: true })
      .filter(r => r.base.compare(base) >= 0 && r.base.compare(base.add(size)) < 0);
    const CH = 0x400000, OV = 8;
    const sites = [];
    for (const r of xranges) {
      let pos = r.base;
      while (pos.compare(r.base.add(r.size)) < 0) {
        const len = Math.min(CH, r.base.add(r.size).sub(pos).toInt32());
        let buf; try { buf = new Uint8Array(pos.readByteArray(len)); } catch (e) { break; }
        for (let i = 0; i + 5 <= buf.length; i++) {
          if (buf[i] !== 0xe8) continue;
          const rel = buf[i+1] | (buf[i+2] << 8) | (buf[i+3] << 16) | (buf[i+4] << 24);
          if (!pos.add(i + 5 + rel).equals(helper)) continue;
          let idx = null, off = null, l2 = null;
          for (let j = Math.max(0, i - 0x20); j < i; j++) {
            if (buf[j] === 0xb9) idx = (buf[j+1] | (buf[j+2] << 8) | (buf[j+3] << 16) | ((buf[j+4] << 24) >>> 0)) >>> 0;
            if (buf[j] === 0xba) off = (buf[j+1] | (buf[j+2] << 8) | (buf[j+3] << 16) | ((buf[j+4] << 24) >>> 0)) >>> 0;
            if (buf[j] === 0x41 && buf[j+1] === 0xb8) l2 = (buf[j+2] | (buf[j+3] << 8) | (buf[j+4] << 16) | ((buf[j+5] << 24) >>> 0)) >>> 0;
            if (buf[j] === 0x45 && buf[j+1] === 0x31 && buf[j+2] === 0xc0) l2 = 0;
          }
          sites.push({ site: pos.add(i).toString(16), idx, off, len: l2 });
        }
        pos = pos.add(len - OV);
      }
    }
    return JSON.stringify({ count: sites.length, sites: sites });
  });
};
