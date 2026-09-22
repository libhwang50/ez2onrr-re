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

// The error-site hunt, split into three fast stages so the Python driver can
// log progress between them and Ctrl-C cancels between stages safely.
//
// Stage 1 (hunt1): anchor the literal-data base via the known zf.aes_key
//   default literal, then locate the Korean message (UTF-8) in that region
//   and dump its neighbourhood (sibling error literals).
// Stage 2 (hunt2, offStr): find the literal THUNK for that data offset
//   (mov edx,<off> before call helper) and its function start.
// Stage 3 (hunt3, funcStr): find the callers of that thunk function and
//   attribute them via the method map.

const HELPER_RVA = 0xc12390;
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

function utf8bytes(s) {
  const bytes = [];
  for (const ch of s) { const c = ch.codePointAt(0);
    if (c < 0x80) bytes.push(c);
    else if (c < 0x800) bytes.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000) bytes.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else bytes.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63)); }
  return new Uint8Array(bytes);
}

// scan [s, e) intersected with each range, with a global byte budget
function boundedScan(sLow, sHigh, pat, budgetObj) {
  const hits = [];
  for (const r of Process.enumerateRanges({ protection: 'r--', coalesce: true })
      .concat(Process.enumerateRanges({ protection: 'rw-', coalesce: true }))) {
    if (budgetObj.n <= 0) break;
    const s = r.base.compare(sLow) > 0 ? r.base : sLow;
    const eEnd = r.base.add(r.size);
    const e = eEnd.compare(sHigh) > 0 ? sHigh : eEnd;
    if (s.compare(e) >= 0) continue;
    const n = e.sub(s).toInt32();
    budgetObj.n -= n;
    try { for (const m of Memory.scanSync(s, n, pat)) {
      hits.push(m.address); if (hits.length >= 8) break;
    } } catch (e) {}
    if (hits.length >= 8) break;
  }
  return hits;
}

rpc.exports.hunt1 = function (korean) {
  return Il2Cpp.perform(() => {
    const out = {};
    const mod = Process.getModuleByName('GameAssembly.dll');
    const base = mod.base;
    out.base = base.toString(16);
    const aesThunk = parseThunk(base.add(AESKEY_THUNK_RVA));
    const ivThunk = parseThunk(base.add(AESIV_THUNK_RVA));
    out.aesThunk = { va: base.add(AESKEY_THUNK_RVA).toString(16), ...aesThunk };
    if (aesThunk.off === null || !aesThunk.len) return JSON.stringify({ ...out, err: 'aes_key thunk unparsed' });

    // default-key literal: intersected scan around the module
    const defPat = utf8bytes(DEFAULT_KEY); const defPatHex = Array.from(defPat).map(b => b.toString(16).padStart(2, '0')).join(' ');
    const defHits = boundedScan(base, base.add(0x8000000), defPatHex, { n: 300000000 });
    out.defHits = defHits.map(a => a.toString(16));
    let litBase = null;
    for (const h of defHits) {
      const cand = h.sub(aesThunk.off);
      try { if (cand.add(ivThunk.off).readUtf16String(16) === DEFAULT_IV) { litBase = cand; break; } } catch (e) {}
    }
    if (!litBase) return JSON.stringify({ ...out, err: 'literal base not anchored' });
    out.litBase = litBase.toString(16);

    // Korean message (UTF-8) in the literal region
    const k8 = utf8bytes(korean); const kPat = Array.from(k8).map(b => b.toString(16).padStart(2, '0')).join(' ');
    const kHits = boundedScan(litBase, litBase.add(0x2000000), kPat, { n: 200000000 });
    out.koreanHits = kHits.map(a => a.toString(16));
    if (!kHits.length) return JSON.stringify({ ...out, err: 'korean utf8 literal not found in literal region' });

    const offK = kHits[0].sub(litBase).toInt32();
    out.koreanOff = offK;

    // neighbourhood dump: ±2 KB of the literal data, decoded as UTF-8,
    // split into runs on NUL / non-text bytes
    const NB = 0x600;
    const s0 = litBase.add(Math.max(0, offK - NB));
    const n0 = (offK - (s0.toInt32() - litBase.toInt32())) + 0xa00;
    const u = new Uint8Array(s0.readByteArray(n0));
    let txt = '', hex = '';
    for (const b of u) hex += b.toString(16).padStart(2, '0');
    const runs = [];
    let cur = '';
    for (const b of u) {
      if ((b >= 0x20 && b < 0x7f) || b >= 0x80) { cur += (b < 0x7f) ? String.fromCharCode(b) : '\uFFFD'; }
      else { if (cur.length >= 4) runs.push(cur); cur = ''; }
    }
    if (cur.length >= 4) runs.push(cur);
    out.neighbourRuns = runs;
    out.neighbourHex = hex;
    out.neighbourStart = s0.toString(16);
    return JSON.stringify(out);
  });
};

rpc.exports.hunt2 = function (offStr) {
  return Il2Cpp.perform(() => {
    const off = parseInt(offStr, 10) >>> 0;
    const mod = Process.getModuleByName('GameAssembly.dll');
    const base = mod.base;
    const helper = base.add(HELPER_RVA);
    // find `mov edx, <off>` followed by `call helper` in the executable ranges
    const offBytes = [off & 0xff, (off >> 8) & 0xff, (off >> 16) & 0xff, (off >>> 24) & 0xff];
    const pat = 'ba ' + offBytes.map(b => b.toString(16).padStart(2, '0')).join(' ');
    const xranges = Process.enumerateRanges({ protection: 'x', coalesce: true })
      .filter(r => r.base.compare(base) >= 0 && r.base.compare(base.add(mod.size)) < 0);
    const CH = 0x400000, OV = 8;
    const found = [];
    for (const r of xranges) {
      let pos = r.base;
      while (pos.compare(r.base.add(r.size)) < 0) {
        const len = Math.min(CH, r.base.add(r.size).sub(pos).toInt32());
        let buf; try { buf = new Uint8Array(pos.readByteArray(len)); } catch (e) { break; }
        for (let i = 0; i + 5 <= buf.length; i++) {
          if (buf[i] !== 0xba) continue;
          let ok = true;
          for (let k = 0; k < 4; k++) if (buf[i+1+k] !== offBytes[k]) { ok = false; break; }
          if (!ok) continue;
          // find the E8 call within the next 24 bytes and verify the helper
          for (let j = i + 5; j < Math.min(i + 28, buf.length - 5); j++) {
            if (buf[j] !== 0xe8) continue;
            const rel = buf[j+1] | (buf[j+2] << 8) | (buf[j+3] << 16) | (buf[j+4] << 24);
            if (pos.add(j + 5 + rel).equals(helper)) {
              const callSite = pos.add(j);
              // function start: last int3 before the body
              let fs = null;
              for (let b = j; b >= Math.max(0, j - 0x80); b--) {
                if (buf[b] === 0xcc) { fs = b + 1; break; }
              }
              found.push({ callSite: callSite.toString(16), funcStart: fs === null ? null : pos.add(fs).toString(16) });
              break;
            }
          }
          if (found.length >= 8) break;
        }
        if (found.length >= 8) break;
        pos = pos.add(len - OV);
      }
      if (found.length >= 8) break;
    }
    return JSON.stringify({ off: off, found: found });
  });
};

rpc.exports.hunt3 = function (funcStr) {
  return Il2Cpp.perform(() => {
    const tva = ptr(funcStr);
    const mod = Process.getModuleByName('GameAssembly.dll');
    const base = mod.base;
    const xranges = Process.enumerateRanges({ protection: 'x', coalesce: true })
      .filter(r => r.base.compare(base) >= 0 && r.base.compare(base.add(mod.size)) < 0);
    const CH = 0x400000, OV = 8;
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
    return JSON.stringify({ func: funcStr, callers: callers.map(cs => {
      const encl = attr(cs);
      return { site: cs, enc: encl ? encl.name + ' @ ' + encl.va.toString(16) : '?' };
    }) });
  });
};

// --- memory probing for the command channel (server/cmd.json) ---------------
// findhex(hexPattern[, budgetMB]) -> every occurrence of the byte pattern in
// rw-/r-- ranges, with a window of context around each hit. Used to locate the
// client's own copy of the session bCK (the value the pattern response must
// echo), which the private server can then serve.
rpc.exports.findhex = function (hexstr, budgetMB) {
  return Il2Cpp.perform(() => {
    const pat = (hexstr || '').trim();
    if (!pat) return JSON.stringify({ err: 'no pattern' });
    const budget = (budgetMB ? parseInt(budgetMB, 10) : 2048) * 1024 * 1024;
    const t0 = Date.now();
    let scanned = 0;
    const hits = [];
    const ranges = Process.enumerateRanges({ protection: 'rw-', coalesce: true })
      .concat(Process.enumerateRanges({ protection: 'r--', coalesce: true }));
    const CHUNK = 64 * 1024 * 1024;          // big ranges are scanned in chunks:
    const plen = Math.floor(pat.split(' ').length);   // skipping them entirely
    for (const r of ranges) {                        // (as an earlier version did)
      if (scanned > budget || Date.now() - t0 > 240000) break;   // hid real hits
      let found = [];
      if (r.size <= CHUNK) {
        scanned += r.size;
        try { found = Memory.scanSync(r.base, r.size, pat); } catch (e) {}
      } else {
        for (let off = 0; off < r.size; off += CHUNK - plen) {
          if (scanned > budget || Date.now() - t0 > 240000) break;
          const len = Math.min(CHUNK, r.size - off);
          scanned += len;
          try { found = found.concat(Memory.scanSync(r.base.add(off), len, pat)); }
          catch (e) {}
        }
      }
      for (const m of found) {
        if (hits.length >= 64) break;
        let ctx = '';
        try {
          const back = Math.min(64, m.address.sub(r.base).toInt32());
          const fwd = 64;
          const buf = new Uint8Array(m.address.sub(back).readByteArray(back + pat.split(' ').length + fwd));
          for (const b of buf) ctx += (b >= 32 && b < 127) ? String.fromCharCode(b) : '.';
        } catch (e) { ctx = 'ctx?'; }
        let hex = '';
        try {
          const hb = new Uint8Array(m.address.sub(16).readByteArray(80));
          for (const b of hb) hex += b.toString(16).padStart(2, '0');
        } catch (e) {}
        hits.push({ addr: m.address.toString(16), ascii: ctx, hex: hex });
      }
    }
    return JSON.stringify({ pattern: pat, scannedMB: Math.round(scanned / 1048576),
                            seconds: ((Date.now() - t0) / 1000).toFixed(1), hits: hits });
  });
};

rpc.exports.readbytes = function (addrStr, lenStr) {
  return Il2Cpp.perform(() => {
    const n = Math.min(4096, parseInt(lenStr, 10) || 64);
    const b = new Uint8Array(ptr(addrStr).readByteArray(n));
    let hex = '', asc = '';
    for (const x of b) { hex += x.toString(16).padStart(2, '0'); asc += (x >= 32 && x < 127) ? String.fromCharCode(x) : '.'; }
    return JSON.stringify({ addr: addrStr, len: n, hex: hex, ascii: asc });
  });
};

// findthunk(targetAddr): the robust replacement for hunt1/hunt2. Instead of
// anchoring the literal-data base via a hardcoded thunk RVA (which goes stale),
// locate the mapped range that CONTAINS the literal, derive the image base from
// its file offset, compute the literal's offset, and search the executable
// ranges for `mov edx,<off>` + a call right after - the literal thunk. Then
// attribute the callers of that thunk to methods, all in one go.
rpc.exports.findthunk = function (targetStr) {
  return Il2Cpp.perform(() => {
    const target = ptr(targetStr);
    const out = { target: targetStr, offsets: [], found: [] };
    let rangeBase = null, imgBase = null, rsize = 0;
    for (const r of Process.enumerateRanges('r--')) {
      if (r.base.compare(target) <= 0 && r.base.add(r.size).compare(target) > 0) {
        rangeBase = r.base; rsize = r.size;
        out.range = r.base.toString(16) + '+0x' + r.size.toString(16)
                  + ' file=' + JSON.stringify(r.file || null);
        if (r.file && typeof r.file.offset === 'number') imgBase = r.base.sub(r.file.offset);
        break;
      }
    }
    if (!rangeBase) return JSON.stringify({ ...out, err: 'no containing r-- range' });
    const cands = [];
    if (imgBase) cands.push({ name: 'imageBase', base: imgBase });
    cands.push({ name: 'rangeBase', base: rangeBase });
    const mod = Process.getModuleByName('GameAssembly.dll');
    const xr = Process.enumerateRanges('x')
      .filter(r => r.base.compare(mod.base) >= 0 && r.base.compare(mod.base.add(mod.size)) < 0);
    for (const c of cands) {
      const off = target.sub(c.base).toInt32() >>> 0;
      out.offsets.push({ name: c.name, base: c.base.toString(16), off: off });
      const ob = [off & 0xff, (off >> 8) & 0xff, (off >> 16) & 0xff, (off >>> 24) & 0xff];
      const pat = 'ba ' + ob.map(b => b.toString(16).padStart(2, '0')).join(' ');
      const CH = 0x400000, OV = 8;
      for (const r of xr) {
        let pos = r.base;
        while (pos.compare(r.base.add(r.size)) < 0) {
          const len = Math.min(CH, r.base.add(r.size).sub(pos).toInt32());
          let buf; try { buf = new Uint8Array(pos.readByteArray(len)); } catch (e) { break; }
          for (let i = 0; i + 6 <= buf.length; i++) {
            if (buf[i] !== 0xba) continue;
            if (buf[i+1] !== ob[0] || buf[i+2] !== ob[1] || buf[i+3] !== ob[2] || buf[i+4] !== ob[3]) continue;
            for (let j = i + 5; j < Math.min(i + 30, buf.length - 5); j++) {
              if (buf[j] !== 0xe8) continue;
              let fs = null;
              for (let b = j; b >= Math.max(0, j - 0x120); b--) if (buf[b] === 0xcc) { fs = b + 1; break; }
              out.found.push({ via: c.name, off: off, callSite: pos.add(j).toString(16),
                               funcStart: fs === null ? null : pos.add(fs).toString(16) });
              break;
            }
          }
          pos = pos.add(len - OV);
        }
      }
    }
    // attribute callers of each resolved function start
    const mmap = [];
    for (const asm of Il2Cpp.domain.assemblies) {
      let img; try { img = asm.image; } catch (e) { continue; }
      let classes; try { classes = img.classes; } catch (e) { continue; }
      for (const cls of classes) {
        let ms; try { ms = cls.methods; } catch (e) { continue; }
        for (const m of ms) { let va; try { va = m.virtualAddress; } catch (e) { continue; }
          if (!va.isNull()) mmap.push({ va: va, name: cls.name + '.' + m.name }); }
      }
    }
    mmap.sort((a, b) => a.va.compare(b.va));
    const attr = (sp) => { let lo = 0, hi = mmap.length - 1, best = null;
      while (lo <= hi) { const mid = (lo + hi) >> 1;
        if (mmap[mid].va.compare(sp) <= 0) { best = mmap[mid]; lo = mid + 1; } else hi = mid - 1; }
      return best; };
    out.funcs = [];
    const seen = {};
    for (const f of out.found) {
      if (!f.funcStart || seen[f.funcStart]) continue;
      seen[f.funcStart] = 1;
      const tva = ptr(f.funcStart);
      const callers = [];
      for (const r of xr) {
        let pos = r.base;
        while (pos.compare(r.base.add(r.size)) < 0) {
          const len = Math.min(0x400000, r.base.add(r.size).sub(pos).toInt32());
          let buf; try { buf = new Uint8Array(pos.readByteArray(len)); } catch (e) { break; }
          for (let i = 0; i + 5 <= buf.length; i++) {
            if (buf[i] !== 0xe8) continue;
            const rel = buf[i+1] | (buf[i+2] << 8) | (buf[i+3] << 16) | (buf[i+4] << 24);
            if (pos.add(i + 5 + rel).equals(tva)) callers.push(pos.add(i).toString(16));
          }
          pos = pos.add(len - 8);
        }
      }
      out.funcs.push({ funcStart: f.funcStart, callers: callers.map(cs => {
        const e = attr(ptr(cs));
        return { site: cs, enc: e ? e.name + ' @ ' + e.va.toString(16) : '?' }; }) });
    }
    return JSON.stringify(out);
  });
};
