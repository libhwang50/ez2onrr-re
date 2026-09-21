// Session-key reader + error-site hunter. Read-only.
//
// readkey: zf.aes_key / zf.aes_iv statics (the API session key).
// hunt(korean): locate a Korean error-message string literal in the mapped
// metadata, find the literal THUNK that serves it (idx/off/len), and attribute
// the code that calls that thunk. All through the ONE session this script
// runs in - extra Frida sessions crash the game.

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

rpc.exports.hunt = function (korean) {
  return Il2Cpp.perform(() => {
    const out = {};
    const mod = Process.getModuleByName('GameAssembly.dll');
    const base = mod.base, size = mod.size;
    out.base = base.toString(16);

    const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    const zf = img.class("zf");

    // 1. zf..cctor -> the literal thunks it calls; each thunk embeds
    //    (ecx=index, edx=data-offset, r8d=length) before `call helper`.
    let cctor = null;
    for (const m of zf.methods) if (m.name === '.cctor') cctor = m.virtualAddress;
    if (!cctor) return JSON.stringify({ err: 'no zf .cctor' });
    const cctorBytes = new Uint8Array(cctor.readByteArray(0x200));
    const thunks = [];
    for (let i = 0; i + 5 <= cctorBytes.length; i++) {
      if (cctorBytes[i] !== 0xe8) continue;
      const rel = cctorBytes[i+1] | (cctorBytes[i+2] << 8) | (cctorBytes[i+3] << 16) | (cctorBytes[i+4] << 24);
      thunks.push({ site: cctor.add(i), va: cctor.add(i + 5 + rel) });
    }
    out.cctor = cctor.toString(16);
    out.cctorThunks = thunks.map(t => t.va.toString(16));

    // 2. parse each thunk body for (idx, off, len)
    const parseThunk = (va) => {
      const b = new Uint8Array(va.readByteArray(0x40));
      let idx = null, off = null, len = null, callRel = null;
      for (let i = 0; i + 5 <= b.length; i++) {
        if (b[i] === 0xb9) idx = b[i+1] | (b[i+2] << 8) | (b[i+3] << 16) | ((b[i+4] << 24) >>> 0);
        if (b[i] === 0xba) off = (b[i+1] | (b[i+2] << 8) | (b[i+3] << 16) | ((b[i+4] << 24) >>> 0)) >>> 0;
        if (b[i] === 0x41 && b[i+1] === 0xb8) len = b[i+2] | (b[i+3] << 8) | (b[i+4] << 16) | ((b[i+5] << 24) >>> 0);
        if (b[i] === 0x45 && b[i+1] === 0x31 && b[i+2] === 0xc0) len = 0;
        if (b[i] === 0xe8) { callRel = b[i+1] | (b[i+2] << 8) | (b[i+3] << 16) | (b[i+4] << 24); break; }
      }
      return { idx, off, len, helper: callRel === null ? null : va.add(i + 5 + callRel) };
    };
    const parsed = thunks.map(t => ({ va: t.va.toString(16), ...parseThunk(t.va) }));
    out.cctorParsed = parsed;

    // 3. anchor the literal-data base with the publicKey literal (the XML):
    //    its managed string is in zf.publicKey; the mapped UTF-16 copy of the
    //    literal sits somewhere in the module's read-only ranges.
    const pkStr = zf.field('publicKey').value;
    const pkChars = pkStr.handle.add(0x14);
    const xmlHead = '<RSAKeyValue';
    const xmlPat = utf16hex(xmlHead).match(/../g).join(' ');
    const xmlHits = [];
    for (const r of Process.enumerateRanges({ protection: 'r--', coalesce: true })) {
      if (r.base.compare(base) < 0 || r.base.compare(base.add(size)) >= 0) continue;
      try { for (const m of Memory.scanSync(r.base, r.size, xmlPat)) {
        xmlHits.push(m.address); if (xmlHits.length >= 8) break;
      } } catch (e) {}
    }
    out.xmlHits = xmlHits.map(a => a.toString(16));

    // candidate bases: for each cctor thunk with a plausible XML length,
    // base = xmlHit - off; verify by reading the full XML at base+off.
    let litBase = null, anchor = null;
    const pkXml = String(pkStr.content);
    for (const p of parsed) {
      if (p.off === null || p.len === null || p.len < 400 || p.len > 700) continue;
      for (const hit of xmlHits) {
        const cand = hit.sub(p.off);
        try {
          const u = new Uint8Array(cand.readByteArray(p.len * 2));
          let s = '';
          for (let i = 0; i + 1 < u.length; i += 2) s += String.fromCharCode(u[i] | (u[i+1] << 8));
          if (s === pkXml) { litBase = cand.sub(0); anchor = { thunk: p, xmlAddr: hit.toString() }; break; }
        } catch (e) {}
      }
      if (litBase) break;
    }
    if (!litBase) return JSON.stringify({ ...out, err: 'literal base not anchored' });
    out.litBase = litBase.toString(16);
    out.anchor = anchor;

    const readLit = (off, len) => {
      try {
        const u = new Uint8Array(litBase.add(off).readByteArray(len * 2));
        let s = '';
        for (let i = 0; i + 1 < u.length; i += 2) s += String.fromCharCode(u[i] | (u[i+1] << 8));
        return s;
      } catch (e) { return null; }
    };

    // 4. scan the module read-only ranges for the Korean needle (UTF-16)
    const kPat = utf16hex(korean).match(/../g).join(' ');
    const kHits = [];
    for (const r of Process.enumerateRanges({ protection: 'r--', coalesce: true })) {
      if (r.base.compare(base) < 0 || r.base.compare(base.add(size)) >= 0) continue;
      try { for (const m of Memory.scanSync(r.base, r.size, kPat)) {
        kHits.push(m.address); if (kHits.length >= 8) break;
      } } catch (e) {}
    }
    out.koreanHits = kHits.map(a => a.toString(16));

    // 5. enumerate ALL literal thunks + callers of the matched thunk(s):
    //    chunked scans over the module's executable ranges (never one huge read)
    const helpers = {};
    for (const p of parsed) if (p.helper) helpers[p.helper.toString()] = true;
    const helperList = Object.keys(helpers).map(h => ptr(h));
    out.helpers = helperList.map(h => h.toString(16));
    const xranges = Process.enumerateRanges({ protection: 'x', coalesce: true })
      .filter(r => r.base.compare(base) >= 0 && r.base.compare(base.add(size)) < 0);
    const CH = 0x400000, OV = 8;
    const allThunks = [], callerSites = [];
    const thunkVAs = matched.map(t => ptr(t.thunk));
    const isHelper = (t) => helperList.some(h => h.equals(t));
    const isMatchedThunk = (t) => thunkVAs.some(tv => tv.equals(t));
    const pass = (collectThunks) => {
      for (const r of xranges) {
        let pos = r.base;
        while (pos.compare(r.base.add(r.size)) < 0) {
          const len = Math.min(CH, r.base.add(r.size).sub(pos).toInt32());
          let buf; try { buf = new Uint8Array(pos.readByteArray(len)); } catch (e) { break; }
          for (let i = 0; i + 5 <= buf.length; i++) {
            if (buf[i] !== 0xe8) continue;
            const rel = buf[i+1] | (buf[i+2] << 8) | (buf[i+3] << 16) | (buf[i+4] << 24);
            const target = pos.add(i + 5 + rel);
            if (collectThunks ? isHelper(target) : isMatchedThunk(target)) {
              const site = pos.add(i);
              if (collectThunks) {
                let idx = null, off = null, len2 = null;
                for (let j = Math.max(0, i - 0x20); j < i; j++) {
                  if (buf[j] === 0xb9) idx = (buf[j+1] | (buf[j+2] << 8) | (buf[j+3] << 16) | ((buf[j+4] << 24) >>> 0)) >>> 0;
                  if (buf[j] === 0xba) off = (buf[j+1] | (buf[j+2] << 8) | (buf[j+3] << 16) | ((buf[j+4] << 24) >>> 0)) >>> 0;
                  if (buf[j] === 0x41 && buf[j+1] === 0xb8) len2 = (buf[j+2] | (buf[j+3] << 8) | (buf[j+4] << 16) | ((buf[j+5] << 24) >>> 0)) >>> 0;
                  if (buf[j] === 0x45 && buf[j+1] === 0x31 && buf[j+2] === 0xc0) len2 = 0;
                }
                if (off !== null) allThunks.push({ thunk: target.toString(16), site: site.toString(16), idx, off, len: len2 });
              } else {
                callerSites.push(site.toString(16));
              }
            }
          }
          pos = pos.add(len - OV);
        }
      }
    };
    pass(true);
    out.thunkCount = allThunks.length;

    // 6. match the Korean literal: data at litBase+off must equal the needle
    const kStarts = kHits.map(a => a.sub(litBase).toInt32());
    const matched = [];
    for (const t of allThunks) {
      if (t.off === null) continue;
      for (const kOff of kStarts) {
        if (t.off === kOff || (t.off <= kOff && t.off + (t.len || 0) > kOff)) { matched.push(t); break; }
      }
    }
    out.koreanThunks = matched;
    if (matched.length) out.koreanThunkVAs = matched.map(t => t.thunk);

    // 7. neighbours: dump the literals adjacent in the data region
    if (matched.length) {
      const m0 = matched[0];
      const around = [];
      for (const t of allThunks) {
        if (t.off === null || t.len === null || t.len === 0 || t.len > 400) continue;
        if (Math.abs(t.off - m0.off) < 0x1000) around.push(t);
      }
      around.sort((a, b) => a.off - b.off);
      out.neighbours = around.map(t => ({ idx: t.idx, off: t.off, len: t.len, text: (readLit(t.off, t.len) || '').slice(0, 120) }));
    }

    // 8. callers of the matched thunk(s) (second chunked pass) + attribution
    if (matched.length) {
      const thunkVAs2 = matched.map(t => ptr(t.thunk));
      const isM = (t) => thunkVAs2.some(tv => tv.equals(t));
      pass(false);
      // build the method map
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
      const attr = (site) => {
        let lo = 0, hi = mmap.length - 1, best = null;
        const sp = ptr(site);
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
