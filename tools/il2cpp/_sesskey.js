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
    const base = mod.base, size = mod.size;
    out.base = base.toString(16);

    // string-literal helper: RVA 0xC12390; thunks do
    //   mov ecx,<index>; mov edx,<byte-offset>; mov r8d,<byte-length>; call helper
    const HELPER_RVA = 0xc12390;
    const helper = base.add(HELPER_RVA);
    out.helper = helper.toString(16);

    const utf8 = (s) => { const e = { enc: null };
      try { return new TextEncoder().encode(s); } catch (e2) {}
      const bytes = []; for (const ch of s) { const c = ch.codePointAt(0);
        if (c < 0x80) bytes.push(c);
        else if (c < 0x800) bytes.push(0xc0 | (c >> 6), 0x80 | (c & 63));
        else if (c < 0x10000) bytes.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
        else bytes.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63)); }
      return new Uint8Array(bytes); };

    // 1. every `call helper` site; recover (idx, off, len) from the movs before;
    //    function start = last int3 (0xcc) before the body (MSVC padding)
    const xranges = Process.enumerateRanges({ protection: 'x', coalesce: true })
      .filter(r => r.base.compare(base) >= 0 && r.base.compare(base.add(size)) < 0);
    const CH = 0x400000, OV = 8;
    const thunks = [];
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
          if (off === null) continue;
          // function start: last 0xcc before the body, within 0x80
          let fs = null;
          for (let j = i; j >= Math.max(0, i - 0x80); j--) {
            if (buf[j] === 0xcc) { fs = j + 1; break; }
          }
          thunks.push({ va: fs === null ? null : pos.add(fs).toString(16), site: pos.add(i).toString(16), idx, off, len: l2 });
        }
        pos = pos.add(len - OV);
      }
    }
    out.thunkCount = thunks.length;

    // 2. find the Korean literal data (UTF-8) in readable memory; derive the
    //    data-section base statistically: for each candidate thunk,
    //    DATA_BASE = hitAddr - off; the right one makes many other thunks
    //    decode as printable UTF-8 text.
    const needle8 = utf8(korean);
    const pat = Array.from(needle8).map(b => b.toString(16).padStart(2, '0')).join(' ');
    const hits = [];
    for (const r of Process.enumerateRanges({ protection: 'r--', coalesce: true })
        .concat(Process.enumerateRanges({ protection: 'rw-', coalesce: true }))) {
      try { for (const m of Memory.scanSync(r.base, r.size, pat)) {
        hits.push(m.address); if (hits.length >= 8) break;
      } } catch (e) {}
      if (hits.length >= 8) break;
    }
    out.koreanHits = hits.map(a => a.toString(16));
    if (!hits.length) return JSON.stringify({ ...out, err: 'korean utf8 literal not found' });

    const printable = (addr, len) => {
      try {
        const u = new Uint8Array(ptr(addr).readByteArray(len));
        let ok = 0;
        for (const b of u) if (b === 0x20 || (b >= 0x30 && b < 0x7f) || b >= 0x80) ok++;
        return ok / len;
      } catch (e) { return 0; }
    };
    let dataBase = null, koreanThunk = null;
    for (const t of thunks) {
      if (t.len === null || t.len < 40) continue;
      for (const h of hits) {
        const cand = h.sub(t.off);
        // cross-validate: 6 other thunks must decode as printable UTF-8
        let good = 0, tried = 0;
        for (const o of thunks) {
          if (o === t || o.len === null || o.len < 8 || o.len > 300) continue;
          tried++;
          if (printable(cand.add(o.off), Math.min(o.len, 64)) > 0.85) good++;
          if (tried >= 8) break;
        }
        if (tried && good / tried >= 0.7) { dataBase = cand; koreanThunk = t; break; }
      }
      if (dataBase) break;
    }
    if (!dataBase) return JSON.stringify({ ...out, err: 'data base not resolved', koreanNeedle: korean });
    out.dataBase = dataBase.toString(16);
    out.koreanThunk = koreanThunk;

    // 3. neighbours: literals adjacent in the data region, decoded as UTF-8
    const dec = (off, len) => {
      try {
        const u = new Uint8Array(dataBase.add(off).readByteArray(len));
        let s = ''; try { s = new TextDecoder('utf-8', { fatal: false }).decode(u); } catch (e2) { s = utf8bad(u); }
        return s;
      } catch (e) { return null; }
    };
    const utf8bad = (u) => { let s = ''; for (const b of u) s += (b >= 32 && b < 128) ? String.fromCharCode(b) : '\u00b7'; return s; };
    const m0 = koreanThunk.off;
    const around = [];
    for (const t of thunks) {
      if (t.len === null || t.len === 0 || t.len > 500) continue;
      if (Math.abs(t.off - m0) < 0x800) around.push(t);
    }
    around.sort((a, b) => a.off - b.off);
    out.neighbours = around.map(t => ({ idx: t.idx, off: t.off, len: t.len, text: (dec(t.off, t.len) || '').slice(0, 200) }));

    // 4. callers of the Korean thunk function + attribution via the method map
    if (koreanThunk.va) {
      const tva = ptr(koreanThunk.va);
      const callers = [];
      for (const r of xranges) {
        let pos = r.base;
        while (pos.compare(r.base.add(r.size)) < 0) {
          const len = Math.min(CH, r.base.add(r.size).sub(pos).toInt32());
          let buf; try { buf = new Uint8Array(pos.readByteArray(len)); } catch (e) { break; }
          for (let i = 0; i + 5 <= buf.length; i++) {
            if (buf[i] !== 0xe8) continue;
            const rel = buf[i+1] | (buf[i+2] << 8) | (buf[i+3] << 16) | (buf[i+4] << 24);
            if (pos.add(i + 5 + rel).equals(tva)) callers.push(pos.add(i).toString(16));
          }
          pos = pos.add(len - OV);
        }
      }
      out.callerSites = callers;
      const mmap = [];
      for (const asm of Il2Cpp.domain.assemblies) {
        let img; try { img = asm.image; } catch (e) { continue; }
        let classes; try { classes = img.classes; } catch (e) { continue; }
        for (const cls of classes) {
          let ms; try { ms = cls.methods; } catch (e) { continue; }
          for (const m of ms) {
            let va; try { va = m.virtualAddress; } catch (e) { continue; }
            if (va.isNull()) continue;
            mmap.push({ va, name: cls.name + '.' + m.name });
          }
          let nc; try { nc = cls.nestedClasses; } catch (e) { continue; }
          for (const n of nc) {
            let ms2; try { ms2 = n.methods; } catch (e) { continue; }
            for (const m of ms2) {
              let va; try { va = m.virtualAddress; } catch (e) { continue; }
              if (va.isNull()) continue;
              mmap.push({ va, name: cls.name + '/' + n.name + '.' + m.name });
            }
          }
        }
      }
      mmap.sort((a, b) => a.va.compare(b.va));
      const attr = (siteStr) => {
        const sp = ptr(siteStr);
        let lo = 0, hi = mmap.length - 1, best = null;
        while (lo <= hi) {
          const mid = (lo + hi) >> 1;
          if (mmap[mid].va.compare(sp) <= 0) { best = mmap[mid]; lo = mid + 1; } else hi = mid - 1;
        }
        return best;
      };
      out.callers = callers.map(cs => {
        const encl = attr(cs);
        return { site: cs, enc: encl ? encl.name + ' @ ' + encl.va.toString(16) : '?' };
      });
    }
    return JSON.stringify(out);
  });
};
