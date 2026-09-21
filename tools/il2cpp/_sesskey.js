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

    // 1. parse the known zf literal thunks -> (idx, off, len) + the shared helper
    const aesThunk = parseThunk(base.add(AESKEY_THUNK_RVA));
    const ivThunk = parseThunk(base.add(AESIV_THUNK_RVA));
    out.aesThunk = { va: base.add(AESKEY_THUNK_RVA).toString(16), ...aesThunk };
    if (aesThunk.off === null || !aesThunk.len || aesThunk.helper === null)
      return JSON.stringify({ ...out, err: 'aes_key thunk unparsed' });

    // 2. find the mapped DEFAULT literal -> literal-data base, cross-checked
    //    against the aes_iv thunk's data
    const defPat = utf16hex(DEFAULT_KEY).match(/../g).join(' ');
    const defHits = [];
    for (const r of Process.enumerateRanges({ protection: 'r--', coalesce: true })
        .concat(Process.enumerateRanges({ protection: 'rw-', coalesce: true }))) {
      if (r.base.compare(base) < 0 || r.base.compare(base.add(0x10000000)) >= 0) continue;
      try { for (const m of Memory.scanSync(r.base, r.size, defPat)) {
        defHits.push(m.address); if (defHits.length >= 8) break;
      } } catch (e) {}
    }
    out.defHits = defHits.map(a => a.toString(16));
    let litBase = null;
    for (const h of defHits) {
      const cand = h.sub(aesThunk.off);
      try {
        if (cand.add(ivThunk.off).readUtf16String(16) === DEFAULT_IV) { litBase = cand; break; }
      } catch (e) {}
    }
    if (!litBase) return JSON.stringify({ ...out, err: 'literal base not anchored' });
    out.litBase = litBase.toString(16);

    const readLit = (off, len) => {
      try {
        const u = new Uint8Array(litBase.add(off).readByteArray(len * 2));
        let s = '';
        for (let i = 0; i + 1 < u.length; i += 2) s += String.fromCharCode(u[i] | (u[i+1] << 8));
        return s;
      } catch (e) { return null; }
    };
    // sanity: the aes_key thunk's own literal must read back as the default
    out.aesLitCheck = readLit(aesThunk.off, aesThunk.len);

    // 3. find the Korean literal inside the literal-data window
    const kPat = utf16hex(korean).match(/../g).join(' ');
    const kHits = [];
    {
      const w1 = litBase.add(0x1000000);
      for (const r of Process.enumerateRanges({ protection: 'r--', coalesce: true })
          .concat(Process.enumerateRanges({ protection: 'rw-', coalesce: true }))) {
        const s = r.base.compare(litBase) > 0 ? r.base : litBase;
        const e = r.base.add(r.size).compare(w1) > 0 ? w1 : r.base.add(r.size);
        if (s.compare(e) >= 0) continue;
        try { for (const m of Memory.scanSync(s, e.sub(s).toInt32(), kPat)) {
          kHits.push(m.address); if (kHits.length >= 8) break;
        } } catch (err) {}
        if (kHits.length >= 8) break;
      }
    }
    out.koreanHits = kHits.map(a => a.toString(16));
    const kOffs = kHits.map(a => a.sub(litBase).toInt32());
    out.koreanOffs = kOffs;

    // 4. enumerate ALL literal thunks: chunked scan of the executable ranges
    //    for `call <helper>`, recovering (idx, off, len) from the movs before
    const helper = aesThunk.helper;
    const xranges = Process.enumerateRanges({ protection: 'x', coalesce: true })
      .filter(r => r.base.compare(base) >= 0 && r.base.compare(base.add(size)) < 0);
    const CH = 0x400000, OV = 8;
    const allThunks = [], callerSites = [];
    const pass = (wantThunk) => {
      for (const r of xranges) {
        let pos = r.base;
        while (pos.compare(r.base.add(r.size)) < 0) {
          const len = Math.min(CH, r.base.add(r.size).sub(pos).toInt32());
          let buf; try { buf = new Uint8Array(pos.readByteArray(len)); } catch (e) { break; }
          for (let i = 0; i + 5 <= buf.length; i++) {
            if (buf[i] !== 0xe8) continue;
            const rel = buf[i+1] | (buf[i+2] << 8) | (buf[i+3] << 16) | (buf[i+4] << 24);
            const target = pos.add(i + 5 + rel);
            if (!target.equals(helper)) { if (!wantThunk && kOffs.length === 0) continue; }
            if (wantThunk) {
              if (!target.equals(helper)) continue;
              let idx = null, off = null, l2 = null;
              for (let j = Math.max(0, i - 0x20); j < i; j++) {
                if (buf[j] === 0xb9) idx = (buf[j+1] | (buf[j+2] << 8) | (buf[j+3] << 16) | ((buf[j+4] << 24) >>> 0)) >>> 0;
                if (buf[j] === 0xba) off = (buf[j+1] | (buf[j+2] << 8) | (buf[j+3] << 16) | ((buf[j+4] << 24) >>> 0)) >>> 0;
                if (buf[j] === 0x41 && buf[j+1] === 0xb8) l2 = (buf[j+2] | (buf[j+3] << 8) | (buf[j+4] << 16) | ((buf[j+5] << 24) >>> 0)) >>> 0;
                if (buf[j] === 0x45 && buf[j+1] === 0x31 && buf[j+2] === 0xc0) l2 = 0;
              }
              if (off !== null) allThunks.push({ thunk: target === null ? null : base.add(0).toString(16) && pos.add(i + 5).toString(16), site: pos.add(i).toString(16), idx, off, len: l2 });
            } else {
              // callers pass: target must be one of the matched thunk VAs
              for (const t of (out.koreanThunkVAs || []).map(a => ptr(a))) {
                if (target.equals(t)) { callerSites.push(pos.add(i).toString(16)); break; }
              }
            }
          }
          pos = pos.add(len - OV);
        }
      }
    };
    pass(true);
    out.thunkCount = allThunks.length;

    // 5. match the Korean literal offsets against the thunk table
    const matched = [];
    for (const t of allThunks) {
      if (t.off === null) continue;
      for (const kOff of kOffs) {
        if (t.off === kOff || (t.off <= kOff && t.off + (t.len || 0) > kOff)) { matched.push(t); break; }
      }
    }
    out.matched = matched;

    // 6. neighbours: literals adjacent in the data region
    if (matched.length) {
      const m0 = matched[0];
      const around = [];
      for (const t of allThunks) {
        if (t.off === null || t.len === null || t.len === 0 || t.len > 400) continue;
        if (Math.abs(t.off - m0.off) < 0x1000) around.push(t);
      }
      around.sort((a, b) => a.off - b.off);
      out.neighbours = around.map(t => ({ idx: t.idx, off: t.off, len: t.len, text: (readLit(t.off, t.len) || '').slice(0, 160) }));
    }

    // 7. callers of the matched thunk(s) + attribution via the method map
    if (matched.length) {
      out.koreanThunkVAs = matched.map(t => t.thunk);
      pass(false);
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
      out.callers = callerSites.map(cs => {
        const encl = attr(cs);
        return { site: cs, enc: encl ? encl.name + ' @ ' + encl.va.toString(16) : '?' };
      });
    }
    return JSON.stringify(out);
  });
};
