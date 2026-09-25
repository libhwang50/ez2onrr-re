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

// pubkey: the live zf.publicKey string plus where its characters actually are.
// The Frida-free patcher (client/ez2on_patch.py) finds that string by scanning
// for <RSAKeyValue>; this read-only call pins the exact value (modulus,
// exponent, length) and the raw address so a host-side scan can be validated
// against the same byte-for-byte blob in one session.
// IL2CPP String layout: [klass 8][monitor 8][length int32 @0x10][chars @0x14].
rpc.exports.pubkey = function () {
  return Il2Cpp.perform(() => {
    const out = {};
    let zf;
    try {
      zf = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("zf");
    } catch (e) { return JSON.stringify({ err: 'class lookup: ' + e }); }
    let v;
    try { v = zf.field("publicKey").value; }
    catch (e) { return JSON.stringify({ err: 'field lookup: ' + e }); }
    try { out.content = v.content; } catch (e) { out.err = String(e); }
    try { out.length = v.content.length; } catch (e) {}
    try { out.handle = v.handle.toString(); } catch (e) {}
    try { out.chars = v.handle.add(0x14).toString(); } catch (e) {}
    // does the raw char buffer match the managed value?
    try {
      out.charsMatches = v.handle.add(0x14).readUtf16String(out.length) === out.content;
    } catch (e) {}
    return JSON.stringify(out);
  });
};

// zfstatics: every static field of a class (default zf) with its live value.
// The API session key is generated client-side per launch; if the bCK payload
// is not derived from aes_key/aes_iv then the material it *is* derived from is
// most likely another static in here (a second key/iv pair for the raw
// channels, a nonce, a hash). Read-only, one RPC, no object retention.
rpc.exports.zfstatics = function (clsName) {
  return Il2Cpp.perform(() => {
    const want = (typeof clsName === 'string' && clsName) ? clsName : 'zf';
    const out = { class: want, fields: [] };
    let klass;
    try {
      klass = Il2Cpp.domain.assembly("Assembly-CSharp").image.class(want);
    } catch (e) {
      out.error = 'class lookup: ' + e;
      return JSON.stringify(out);
    }
    let fields = [];
    try { fields = klass.fields; } catch (e) { out.error = 'fields: ' + e; }
    for (const f of fields) {
      const rec = {};
      try { rec.name = f.name; } catch (e) { rec.name = '?'; }
      try { rec.type = f.type && f.type.name; } catch (e) {}
      try { rec.off = f.offset; } catch (e) {}
      let v = null;
      try { v = f.value; } catch (e) { rec.err = String(e); }
      try {
        if (v === null || v === undefined) { rec.value = null; }
        else if (typeof v === 'string') { rec.value = v; }
        else {
          let c;
          try { c = v.content; } catch (e) {}
          if (typeof c === 'string') { rec.value = c; }
          else {
            let h = null, n = null;
            try { h = v.handle; } catch (e) {}
            try { n = v.length; } catch (e) {}
            if (h !== null && typeof n === 'number' && n > 0) {
              rec.ptr = h.toString();
              const cap = Math.min(n, 128);
              let bytes = '';
              try {
                const raw = new Uint8Array(h.add(0x20).readByteArray(cap));
                for (let i = 0; i < raw.length; i++) {
                  bytes += raw[i].toString(16).padStart(2, '0');
                }
                rec.value = 'array[' + n + '] ' + bytes + (n > cap ? '...' : '');
              } catch (e) {
                rec.value = 'array[' + n + '] (read failed: ' + e + ')';
              }
            } else { if (h !== null) { rec.ptr = h.toString(); } rec.value = String(v); }
          }
        }
      } catch (e) { rec.value = 'ERR ' + e; }
      out.fields.push(rec);
    }
    return JSON.stringify(out);
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


// Only the module's OWN executable ranges. The previous filter
// (base >= mod.base && base < mod.base + mod.size) also matched unrelated
// executable mappings in that window - Wine/Unity JIT regions - so byte-by-byte
// JS loops walked gigabytes: that is why the "callers" scan appeared to hang
// while native scanSync (about 1 GB/s) merely took seconds.
function moduleCodeRanges(mod) {
  // Hard cap: never scan outside [mod.base, mod.base + 64 MB). GameAssembly.dll
  // is ~26 MB, so anything beyond that is a different (JIT/Wine) mapping that
  // merely sits in the same address window - including it made JS byte loops
  // walk gigabytes.
  const CAP = 64 * 1024 * 1024;
  const lo = mod.base;
  const hi = mod.base.add(CAP);
  let rs = [];
  try { rs = mod.enumerateRanges('r-x'); } catch (e) { rs = []; }
  if (!rs.length)
    rs = Process.enumerateRanges('x')
      .filter(r => r.base.compare(lo) >= 0 && r.base.compare(hi) < 0);
  const out = [];
  for (const r of rs) {
    if (r.base.compare(lo) < 0 || r.base.compare(hi) >= 0) continue;
    const size = Math.min(typeof r.size === 'number' ? r.size : 0, CAP);
    if (size > 0) out.push({ base: r.base, size: size });
  }
  out.sort((a, b) => a.base.compare(b.base));
  return out;
}

function describeRanges(rs) {
  let total = 0;
  const list = rs.map(r => { total += r.size;
    return r.base.toString(16) + '+0x' + r.size.toString(16); });
  return { ranges: list, totalMB: Math.round(total / 1048576) };
}

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
    const xranges = moduleCodeRanges(mod);
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
    const xranges = moduleCodeRanges(mod);
    const CH = 0x400000, OV = 8;
    const callers = [];
    const tvaNum = parseInt(tva.toString(16), 16);
    for (const r of xranges) {
      let pos = 0;
      const rstart = parseInt(r.base.toString(16), 16);
      while (pos < r.size) {
        const len = Math.min(CH, r.size - pos);
        let buf; try { buf = new Uint8Array(r.base.add(pos).readByteArray(len)); } catch (e) { break; }
        for (let i = 0; i + 5 <= buf.length; i++) {
          if (buf[i] !== 0xe8) continue;
          const rel = buf[i+1] | (buf[i+2] << 8) | (buf[i+3] << 16) | (buf[i+4] << 24);
          if (rstart + pos + i + 5 + rel === tvaNum)
            callers.push('0x' + (rstart + pos + i).toString(16));
        }
        pos += len - OV;
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
    // NOTE: the budget used to default to 2 GB and the scan tried rw- first, so
    // on a process with more memory than that it was exhausted on the heap and
    // the code ranges were never searched at all - which silently produced
    // "0 hits" for instruction/pointer searches. Default is now large, and the
    // result reports whether the budget ran out.
    const budget = (budgetMB ? parseInt(budgetMB, 10) : 16384) * 1024 * 1024;
    const t0 = Date.now();
    let scanned = 0;
    const hits = [];
    // r-x matters too: searching for an instruction pattern (e.g. `mov r8d,<len>`)
    // needs the code ranges, which the earlier version never scanned
    // executable first: a code search must not be starved by the heap
    const ranges = Process.enumerateRanges({ protection: 'r-x', coalesce: true })
      .concat(Process.enumerateRanges({ protection: 'r--', coalesce: true }))
      .concat(Process.enumerateRanges({ protection: 'rw-', coalesce: true }));
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
        let prot = ''; try { prot = Process.findRangeByAddress(m.address).protection; } catch (e) {}
        hits.push({ addr: '0x' + m.address.toString(16), ascii: ctx, hex: hex, prot: prot });
      }
    }
    return JSON.stringify({ pattern: pat, scannedMB: Math.round(scanned / 1048576),
                            budgetMB: Math.round(budget / 1048576),
                            budgetExhausted: scanned >= budget,
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
// findthunk(targetAddr): find the code that references the literal at
// targetAddr. The literal data lives in an anonymous r-- mapping (the metadata
// is decrypted into memory), so the offset the code uses may be relative to a
// different base than the containing range. Try every range base near the target,
// and additionally provide findlit(length) - a base-free scan that keys off the
// literal's LENGTH (`mov r8d,<len>` before the literal-helper call).
rpc.exports.findthunk = function (targetStr, extraBasesCsv) {
  return Il2Cpp.perform(() => {
    const t0 = Date.now();
    const target = ptr(targetStr);
    const mod = Process.getModuleByName('GameAssembly.dll');
    const out = { target: targetStr, basesTried: [], sites: [], uniqueMethods: [] };

    // candidate bases: the containing range's base plus the base of every r--
    // range within 96 MB (covers a separately-mapped metadata image)
    const cands = []; const seen = {};
    const add = (b, tag) => { const k = b.toString(16);
      if (!seen[k]) { seen[k] = 1; cands.push({ name: tag, base: b }); } };
    for (const r of Process.enumerateRanges('r--')) {
      if (r.base.compare(target) <= 0 && r.base.add(r.size).compare(target) > 0) {
        out.range = r.base.toString(16) + '+0x' + r.size.toString(16)
                  + ' file=' + JSON.stringify(r.file || null);
        add(r.base, 'containing');
        if (r.file && typeof r.file.offset === 'number')
          add(r.base.sub(r.file.offset), 'imgOfContaining');
      }
    }
    const lo = target.sub(96 * 1024 * 1024), hi = target.add(96 * 1024 * 1024);
    for (const r of Process.enumerateRanges('r--'))
      if (r.base.compare(lo) > 0 && r.base.compare(hi) < 0) add(r.base, 'nearby');
    if (extraBasesCsv) for (const b of String(extraBasesCsv).split(','))
      if (b.trim()) add(ptr(b.trim()), 'given');

    const xr = moduleCodeRanges(mod);

    for (const c of cands) {
      if (c.base.compare(target) >= 0) continue;   // base above target -> nonsense
      const off = target.sub(c.base).toInt32() >>> 0;
      const ob = [off & 0xff, (off >> 8) & 0xff, (off >> 16) & 0xff, (off >>> 24) & 0xff];
      const pat = 'ba ' + ob.map(b => b.toString(16).padStart(2, '0')).join(' ');
      let hits = 0;
      for (const r of xr) {
        let h; try { h = Memory.scanSync(r.base, r.size, pat); } catch (e) { continue; }
        for (const m of h) {
          hits++;
          if (out.sites.length >= 24) break;
          let buf; try { buf = new Uint8Array(m.address.readByteArray(40)); } catch (e) { continue; }
          let callAt = -1;
          for (let j = 5; j < 34; j++) if (buf[j] === 0xe8) { callAt = j; break; }
          out.sites.push({ base: c.name + ':' + c.base.toString(16), off: off,
                           site: '0x' + m.address.toString(16),
                           callAt: callAt < 0 ? null : m.address.add(callAt).toString(16) });
        }
      }
      out.basesTried.push({ name: c.name, base: c.base.toString(16), off: off, hits: hits });
    }
    out.sites = out.sites.map(s => {
      const e = out.__attr ? out.__attr(ptr(s.site)) : null; return s;
    });

    // attribute the sites to enclosing methods (one method map build)
    const mmap = [];
    for (const asm of Il2Cpp.domain.assemblies) {
      let img, classes;
      try { img = asm.image; } catch (e) { continue; }
      try { classes = img.classes; } catch (e) { continue; }
      for (const cls of classes) {
        let ms; try { ms = cls.methods; } catch (e) { ms = []; }
        for (const m of ms) {
          let va; try { va = m.virtualAddress; } catch (e) { continue; }
          if (!va.isNull()) mmap.push({ va: va, name: (cls.namespace ? cls.namespace + '.' : '') + cls.name + '.' + m.name });
        }
      }
    }
    mmap.sort((a, b) => a.va.compare(b.va));
    const attr = (sp) => { let lo2 = 0, hi2 = mmap.length - 1, best = null;
      while (lo2 <= hi2) { const mid = (lo2 + hi2) >> 1;
        if (mmap[mid].va.compare(sp) <= 0) { best = mmap[mid]; lo2 = mid + 1; } else hi2 = mid - 1; }
      return best; };
    for (const s of out.sites) {
      const e = attr(ptr(s.site));
      s.inMethod = e ? e.name + ' @ ' + e.va.toString(16) : '?';
    }
    out.uniqueMethods = [...new Set(out.sites.map(s => s.inMethod))];
    out.elapsedSec = ((Date.now() - t0) / 1000).toFixed(1);
    return JSON.stringify(out);
  });
};

// findlit(length): base-free. The literal helper is called with r8d = the
// literal's length, so scanning for `mov r8d,<len>` immediately before a call
// finds every code path that references a literal of that length. For each hit
// we also report the `mov edx,<imm32>` (the literal offset) so the correct base
// can be derived as literalAddress - imm32.
rpc.exports.findlit = function (lenStr, targetStr) {
  return Il2Cpp.perform(() => {
    const t0 = Date.now();
    const len = parseInt(lenStr, 10) || 0;
    const lb = [len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff, (len >>> 24) & 0xff];
    const pat = '41 b8 ' + lb.map(b => b.toString(16).padStart(2, '0')).join(' ');
    const mod = Process.getModuleByName('GameAssembly.dll');
    const xr = moduleCodeRanges(mod);
    const out = { len: len, target: targetStr || null, sites: [], uniqueMethods: [] };
    const cands = [];
    for (const r of xr) {
      let h; try { h = Memory.scanSync(r.base, r.size, pat); } catch (e) { continue; }
      for (const m of h) {
        if (out.sites.length >= 40) break;
        let back; try { back = new Uint8Array(m.address.sub(24).readByteArray(24 + 48)); }
        catch (e) { continue; }
        let edxImm = null;
        for (let j = 0; j + 5 <= 24; j++)
          if (back[j] === 0xba) edxImm = back[j+1] | (back[j+2] << 8) | (back[j+3] << 16) | ((back[j+4] << 24) >>> 0);
        let callRel = null, callIdx = -1;
        for (let j = 24; j + 5 <= back.length; j++)
          if (back[j] === 0xe8) {
            callRel = back[j+1] | (back[j+2] << 8) | (back[j+3] << 16) | (back[j+4] << 24);
            callIdx = j; break;
          }
        let rawHex = '';
        try {
          const start = m.address.sub(24);
          const b2 = new Uint8Array(start.readByteArray(72));
          for (const x of b2) rawHex += x.toString(16).padStart(2, '0');
        } catch (e) {}
        out.sites.push({ site: '0x' + m.address.toString(16), rawHex: rawHex, edxImm: edxImm,
                         callAt: callIdx < 0 ? null : m.address.sub(24).add(callIdx).toString(16),
                         callTarget: callIdx < 0 ? null : m.address.sub(24).add(callIdx + 5 + callRel).toString(16),
                         impliedBase: (edxImm !== null && targetStr)
                           ? ptr(targetStr).sub(edxImm).toString(16) : null });
      }
    }
    const mmap = [];
    for (const asm of Il2Cpp.domain.assemblies) {
      let img, classes;
      try { img = asm.image; } catch (e) { continue; }
      try { classes = img.classes; } catch (e) { continue; }
      for (const cls of classes) {
        let ms; try { ms = cls.methods; } catch (e) { ms = []; }
        for (const m of ms) { let va; try { va = m.virtualAddress; } catch (e) { continue; }
          if (!va.isNull()) mmap.push({ va: va, name: (cls.namespace ? cls.namespace + '.' : '') + cls.name + '.' + m.name }); }
      }
    }
    mmap.sort((a, b) => a.va.compare(b.va));
    const attr = (sp) => { let lo2 = 0, hi2 = mmap.length - 1, best = null;
      while (lo2 <= hi2) { const mid = (lo2 + hi2) >> 1;
        if (mmap[mid].va.compare(sp) <= 0) { best = mmap[mid]; lo2 = mid + 1; } else hi2 = mid - 1; }
      return best; };
    for (const s of out.sites) {
      const e = attr(ptr(s.site));
      s.inMethod = e ? e.name + ' @ ' + e.va.toString(16) : '?';
    }
    out.uniqueMethods = [...new Set(out.sites.map(s => s.inMethod))];
    out.elapsedSec = ((Date.now() - t0) / 1000).toFixed(1);
    return JSON.stringify(out);
  });
};

// findlea(targetAddr): find the code that addresses the literal at targetAddr.
// In this build literals are reached with a RIP-relative `lea` (e.g.
// `mov r8d,<len>; lea rcx,[rip+disp32]; ...; call`), not with the
// `mov edx,<offset>` + runtime-base scheme the older notes describe - which is
// why every base-relative scan found nothing. Scan every RIP-relative LEA
// ModRM form, compute the target, and attribute the hit to its method.
rpc.exports.findlea = function (targetStr) {
  return Il2Cpp.perform(() => {
    const t0 = Date.now();
    const target = parseInt(String(targetStr).replace(/^0x/, ''), 16);
    const mod = Process.getModuleByName('GameAssembly.dll');
    const xr = moduleCodeRanges(mod);
    const out = { target: '0x' + target.toString(16), module: mod.base.toString(16),
                  scannedRanges: xr.length, hits: [], uniqueMethods: [] };
    const modrms = [0x05, 0x0d, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d];
    const rexes = [0x48, 0x4c];
    for (const rex of rexes) {
      for (const mrm of modrms) {
        const pat = rex.toString(16) + ' 8d ' + mrm.toString(16);
        for (const r of xr) {
          let hits; try { hits = Memory.scanSync(r.base, r.size, pat); } catch (e) { continue; }
          for (const h of hits) {
            if (out.hits.length >= 80) break;
            let disp;
            try { disp = h.address.add(3).readS32(); } catch (e) { continue; }
            const site = parseInt(h.address.toString(16), 16);
            const tgt = site + 7 + disp;
            if (tgt === target)
              out.hits.push({ site: '0x' + site.toString(16), disp: disp,
                              instr: rex.toString(16) + ' 8d ' + mrm.toString(16) });
          }
        }
      }
    }
    const mmap = [];
    for (const asm of Il2Cpp.domain.assemblies) {
      let img, classes;
      try { img = asm.image; } catch (e) { continue; }
      try { classes = img.classes; } catch (e) { continue; }
      for (const cls of classes) {
        let ms; try { ms = cls.methods; } catch (e) { ms = []; }
        for (const m of ms) { let va; try { va = m.virtualAddress; } catch (e) { continue; }
          if (!va.isNull()) mmap.push({ va: va, name: (cls.namespace ? cls.namespace + '.' : '') + cls.name + '.' + m.name }); }
      }
    }
    mmap.sort((a, b) => a.va.compare(b.va));
    const attr = (sp) => { let lo = 0, hi = mmap.length - 1, best = null;
      while (lo <= hi) { const mid = (lo + hi) >> 1;
        if (mmap[mid].va.compare(sp) <= 0) { best = mmap[mid]; lo = mid + 1; } else hi = mid - 1; }
      return best; };
    for (const h of out.hits) {
      const e = attr(ptr(h.site));
      h.inMethod = e ? e.name + ' @ ' + e.va.toString(16) : '?';
      h.delta = e ? (parseInt(h.site, 16) - parseInt(e.va.toString(16), 16)) : null;
    }
    out.uniqueMethods = [...new Set(out.hits.map(h => h.inMethod))];
    out.elapsedSec = ((Date.now() - t0) / 1000).toFixed(1);
    return JSON.stringify(out);
  });
};

// deref(addr, offsetsCsv): follow a pointer chain - read the 8-byte pointer at
// `addr`, then at each successive +offset - and report every step. Used for the
// literal accessor helpers, whose sequence is
//     mov rcx,[rip+GLOBAL]      ; the System.String Il2CppClass*
//     mov rcx,[rcx+0xb8]        ; klass->static_fields
//     mov rdx,[rcx+STATIC_OFF]  ; the assembly's literal blob base
// so `deref <GLOBAL> 0xb8,0x8320` yields the base in one call.
rpc.exports.deref = function (addrStr, offsCsv) {
  return Il2Cpp.perform(() => {
    const steps = [];
    let cur = ptr(String(addrStr).startsWith('0x') ? addrStr : '0x' + addrStr);
    const offs = String(offsCsv || '').split(',').map(x => x.trim()).filter(Boolean);
    try {
      let v = cur.readPointer();
      steps.push({ at: cur.toString(16), read: v.toString(16) });
      cur = v;
    } catch (e) { return JSON.stringify({ err: 'readPointer failed: ' + e, steps: steps }); }
    for (const o of offs) {
      const off = parseInt(o, 16);
      try {
        const v = cur.add(off).readPointer();
        steps.push({ at: cur.add(off).toString(16), off: o, read: v.toString(16) });
        cur = v;
      } catch (e) { return JSON.stringify({ err: 'chain failed at +' + o + ': ' + e, steps: steps }); }
    }
    return JSON.stringify({ steps: steps, final: '0x' + cur.toString(16) });
  });
};

// findaccessor(offsetHex[, lenHex]): the payload accessor for one literal.
// An accessor looks like
//     mov edx,<offset>       BA imm32   <- the literal's offset in the blob
//     mov r8d,<length>       41 B8 imm32
//     mov ecx,<index>        B9 imm32
//     call <per-assembly helper>
// so scanning for the offset finds the single accessor for that literal (the
// <PrivateImplementationDetails>{...}.a.XX method), and a caller sweep on that
// accessor yields the game methods that use the literal.
rpc.exports.findaccessor = function (offsetStr, lenStr) {
  return Il2Cpp.perform(() => {
    const t0 = Date.now();
    const off = parseInt(String(offsetStr).replace(/^0x/, ''), 16) >>> 0;
    const ob = [off & 0xff, (off >> 8) & 0xff, (off >> 16) & 0xff, (off >>> 24) & 0xff];
    const pat = 'ba ' + ob.map(b => b.toString(16).padStart(2, '0')).join(' ');
    const mod = Process.getModuleByName('GameAssembly.dll');
    const xr = moduleCodeRanges(mod);
    const out = { offset: '0x' + off.toString(16), length: lenStr || null,
                  sites: [], accessors: [], callers: [] };
    for (const r of xr) {
      let hits; try { hits = Memory.scanSync(r.base, r.size, pat); } catch (e) { continue; }
      for (const h of hits) {
        if (out.sites.length >= 16) break;
        let buf;
        try { buf = new Uint8Array(h.address.readByteArray(128)); } catch (e) { continue; }
        // Lenient: some accessors set their arguments in a different order or
        // spread further apart, so a site is reported even when no `mov r8d,<len>`
        // or call is found nearby - the enclosing method is what matters.
        let len2 = null, idx = null, callRel = null, callAt = -1;
        for (let j = 5; j + 5 <= 96; j++) {
          if (buf[j] === 0x41 && buf[j+1] === 0xb8 && len2 === null)
            len2 = (buf[j+2] | (buf[j+3] << 8) | (buf[j+4] << 16) | ((buf[j+5] << 24) >>> 0)) >>> 0;
          if (buf[j] === 0xb9 && idx === null)
            idx = (buf[j+1] | (buf[j+2] << 8) | (buf[j+3] << 16) | ((buf[j+4] << 24) >>> 0)) >>> 0;
          if (buf[j] === 0xe8 && callAt < 0) { callRel = buf[j+1] | (buf[j+2] << 8) | (buf[j+3] << 16) | (buf[j+4] << 24);
                                               callAt = j; }
        }
        if (lenStr && len2 !== null && len2 !== (parseInt(lenStr, 10) >>> 0)) continue;
        out.sites.push({ site: '0x' + h.address.toString(16), off: off, len: len2, idx: idx,
                         callAt: callAt < 0 ? null : h.address.add(callAt).toString(16),
                         helper: callAt < 0 ? null : h.address.add(callAt + 5 + callRel).toString(16) });
      }
    }
    // attribute the sites (the accessor methods) and build the method map
    const mmap = [];
    for (const asm of Il2Cpp.domain.assemblies) {
      let img, classes;
      try { img = asm.image; } catch (e) { continue; }
      try { classes = img.classes; } catch (e) { continue; }
      for (const cls of classes) {
        let ms; try { ms = cls.methods; } catch (e) { ms = []; }
        for (const m of ms) { let va; try { va = m.virtualAddress; } catch (e) { continue; }
          if (!va.isNull()) mmap.push({ va: va, name: (cls.namespace ? cls.namespace + '.' : '') + cls.name + '.' + m.name }); }
      }
    }
    mmap.sort((a, b) => a.va.compare(b.va));
    const attr = (sp) => { let lo = 0, hi = mmap.length - 1, best = null;
      while (lo <= hi) { const mid = (lo + hi) >> 1;
        if (mmap[mid].va.compare(sp) <= 0) { best = mmap[mid]; lo = mid + 1; } else hi = mid - 1; }
      return best; };
    // The caller sweep is deliberately NOT done here: it is the only slow step
    // (a byte-by-byte pass over the whole code section) and running it inline
    // meant an abandoned RPC could wedge the Gadget. Report the accessor (fast),
    // then fetch its callers separately with hunt3.
    for (const s of out.sites) {
      const e = attr(ptr(s.site));
      s.accessor = e ? e.name + ' @ ' + e.va.toString(16) : '?';
      s.accessorVA = e ? '0x' + e.va.toString(16) : null;
      if (e) out.accessors.push(s.accessor);
    }
    out.accessors = [...new Set(out.accessors)];
    out.hint = 'for the callers: python server/_mem.py hunt3 ' +
               (out.sites.length && out.sites[0].accessorVA ? out.sites[0].accessorVA : '<accessorVA>');
    out.elapsedSec = ((Date.now() - t0) / 1000).toFixed(1);
    return JSON.stringify(out);
  });
};

// findlitoff(targetAddr, staticFieldsHex): resolve which assembly blob contains
// the literal at targetAddr and whether the code addresses it.
//
// The literal blobs and the static-fields region share one anonymous mapping, and
// each assembly's blob pointer is stored as an 8-byte pointer inside the
// static-fields region (readable as [StringKlass+0xb8] for the String class, i.e.
// the value `deref <global> 0xb8` returns). So: scan that region for pointers
// into the mapping, and for every candidate base B test whether the code contains
// `mov edx,<target-B>` (BA imm32) - a hit means B is the base of the assembly
// whose blob holds the literal, and the site is the literal's accessor.
rpc.exports.findlitoff = function (targetStr, sfStr) {
  return Il2Cpp.perform(() => {
    const t0 = Date.now();
    const target = parseInt(String(targetStr).replace(/^0x/, ''), 16);
    const sf = parseInt(String(sfStr).replace(/^0x/, ''), 16);
    const out = { target: '0x' + target.toString(16), staticFields: '0x' + sf.toString(16),
                  bases: [], hits: [] };
    // 1) collect pointers inside the static-fields region that point into it
    const lo = sf, hi = sf + 0x2000000;           // pointers into the mapping
    const CH = 0x40000;
    const seen = {};
    for (let off = 0; off < 0x200000 && off < hi - sf; off += CH - 8) {
      const len = Math.min(CH, 0x200000 - off);
      let buf;
      try { buf = new Uint8Array(ptr(sf + off).readByteArray(len)); } catch (e) { break; }
      for (let i = 0; i + 8 <= buf.length; i += 1) {
        const v = buf[i] | (buf[i+1] << 8) | (buf[i+2] << 16) | (buf[i+3] << 24)
                + 0;                                   // low 32 bits
        const vhi = buf[i+4] | (buf[i+5] << 8) | (buf[i+6] << 16) | (buf[i+7] << 24);
        if (vhi !== 0) continue;                        // keep 32-bit addresses
        if (v >= lo && v < hi && v <= target) seen[v] = (off + i);
      }
    }
    const bases = Object.keys(seen).map(k => parseInt(k, 10)).sort((a, b) => a - b);
    out.baseCount = bases.length;
    for (const b of bases) {
      const off2 = target - b;
      if (off2 < 0 || off2 > 0x400000) continue;
      out.bases.push({ base: '0x' + b.toString(16), off: '0x' + off2.toString(16),
                       pointerAt: '0x' + (sf + seen[b]).toString(16) });
    }
    // 2) for each candidate, does the code contain `mov edx,<off>`?
    const mod = Process.getModuleByName('GameAssembly.dll');
    const xr = moduleCodeRanges(mod);
    for (const cand of out.bases) {
      const off2 = parseInt(cand.off, 16);
      const ob = [off2 & 0xff, (off2 >> 8) & 0xff, (off2 >> 16) & 0xff, (off2 >>> 24) & 0xff];
      const pat = 'ba ' + ob.map(x => x.toString(16).padStart(2, '0')).join(' ');
      let n = 0, firstSite = null;
      for (const r of xr) {
        let hs; try { hs = Memory.scanSync(r.base, r.size, pat); } catch (e) { continue; }
        if (hs.length && !firstSite) firstSite = '0x' + hs[0].address.toString(16);
        n += hs.length;
      }
      cand.baHits = n;
      cand.firstSite = firstSite;
    }
    out.candidatesWithHits = out.bases.filter(b => b.baHits > 0);
    out.elapsedSec = ((Date.now() - t0) / 1000).toFixed(1);
    return JSON.stringify(out);
  });
};

// callers(targetVA): raw call-site scan, no method-map build. hunt3 does the same
// scan but then enumerates ~176k methods through the bridge for attribution, and
// that enumeration is what makes it take minutes. This returns the site
// addresses (fast) so the surrounding code can be read and disassembled directly.
rpc.exports.callers = function (targetStr) {
  return Il2Cpp.perform(() => {
    const t0 = Date.now();
    const mod = Process.getModuleByName('GameAssembly.dll');
    const tvaNum = parseInt(String(targetStr).replace(/^0x/, ''), 16);
    const xr = moduleCodeRanges(mod);
    const sites = [];
    let bytesScanned = 0;
    for (const r of xr) {
      const rstart = parseInt(r.base.toString(16), 16);
      let pos = 0;
      while (pos < r.size) {
        const len = Math.min(0x800000, r.size - pos);
        let buf; try { buf = new Uint8Array(r.base.add(pos).readByteArray(len)); } catch (e) { break; }
        bytesScanned += buf.length;
        for (let i = 0; i + 5 <= buf.length; i++) {
          if (buf[i] !== 0xe8) continue;
          const rel = buf[i+1] | (buf[i+2] << 8) | (buf[i+3] << 16) | (buf[i+4] << 24);
          if (rstart + pos + i + 5 + rel === tvaNum)
            sites.push('0x' + (rstart + pos + i).toString(16));
        }
        pos += len - 8;
      }
    }
    const info = describeRanges(xr);
    return JSON.stringify({ target: '0x' + tvaNum.toString(16),
                            ranges: info.ranges, rangeCount: xr.length,
                            rangeTotalMB: info.totalMB,
                            scannedMB: Math.round(bytesScanned / 1048576),
                            sites: sites, count: sites.length,
                            elapsedSec: ((Date.now() - t0) / 1000).toFixed(1) });
  });
};

// --- chunked, abortable code scans -------------------------------------------
// A single full-module scan in the gadget's JS engine takes long enough that
// abandoning it can wedge the Gadget, and it prints nothing meanwhile. These ops
// scan ONE bounded chunk per RPC (the Python client loops), so every call is
// short, progress is visible, and Ctrl-C is safe between chunks.
function codeLayout(mod) {
  const CAP = 64 * 1024 * 1024;
  const lo = mod.base, hi = mod.base.add(CAP);
  let rs = [];
  try { rs = mod.enumerateRanges('r-x'); } catch (e) { rs = []; }
  if (!rs.length)
    rs = Process.enumerateRanges('x').filter(r => r.base.compare(lo) >= 0 && r.base.compare(hi) < 0);
  const out = [];
  for (const r of rs) {
    if (r.base.compare(lo) < 0 || r.base.compare(hi) >= 0) continue;
    const size = Math.min(typeof r.size === 'number' ? r.size : 0, CAP);
    if (size > 0) out.push({ base: r.base, size: size });
  }
  out.sort((a, b) => a.base.compare(b.base));
  return out;
}

function scanChunkFor(targetNum, idx, CH) {
  const mod = Process.getModuleByName('GameAssembly.dll');
  const layout = codeLayout(mod);
  const total = layout.reduce((a, r) => a + r.size, 0);
  const start = idx * CH, end = Math.min(start + CH, total);
  const res = { index: idx, totalMB: Math.round(total / 1048576),
                ranges: layout.map(r => r.base.toString(16) + '+0x' + r.size.toString(16)),
                done: end >= total, sites: [] };
  if (start >= total) { res.done = true; return res; }
  let consumed = 0;
  for (const r of layout) {
    const rStart = consumed, rEnd = consumed + r.size; consumed = rEnd;
    if (rEnd <= start || rStart >= end) continue;
    const from = Math.max(start, rStart) - rStart;
    const to = Math.min(end, rEnd) - rStart;
    const len = to - from;
    let buf;
    try { buf = new Uint8Array(r.base.add(from).readByteArray(len)); } catch (e) { continue; }
    const baseNum = parseInt(r.base.toString(16), 16) + from;
    for (let i = 0; i + 5 <= buf.length; i++) {
      if (buf[i] !== 0xe8) continue;
      const rel = buf[i+1] | (buf[i+2] << 8) | (buf[i+3] << 16) | (buf[i+4] << 24);
      if (baseNum + i + 5 + rel === targetNum)
        res.sites.push('0x' + (baseNum + i).toString(16));
    }
  }
  res.chunkMB = Math.round((end - start) / 1048576);
  return res;
}

rpc.exports.scanCallersChunk = function (targetStr, idxStr, chunkMBStr) {
  return Il2Cpp.perform(() => {
    const target = parseInt(String(targetStr).replace(/^0x/, ''), 16);
    const CH = (parseInt(chunkMBStr, 10) || 2) * 1024 * 1024;
    return JSON.stringify(scanChunkFor(target, parseInt(idxStr, 10) || 0, CH));
  });
};

// method(addrCsv): nearest preceding method for each address, with its name. The
// method-map build is the only cost (~6 s) and needs no code scan, so this is a
// cheap way to name a call target or a containing function once an address is
// known from disassembly.
rpc.exports.method = function (addrCsv) {
  return Il2Cpp.perform(() => {
    const t0 = Date.now();
    const addrs = String(addrCsv || '').split(',').map(x => x.trim()).filter(Boolean);
    const mmap = [];
    for (const asm of Il2Cpp.domain.assemblies) {
      let img, classes;
      try { img = asm.image; } catch (e) { continue; }
      try { classes = img.classes; } catch (e) { continue; }
      for (const cls of classes) {
        let ms; try { ms = cls.methods; } catch (e) { ms = []; }
        for (const m of ms) { let va; try { va = m.virtualAddress; } catch (e) { continue; }
          if (!va.isNull()) mmap.push({ va: va, name: (cls.namespace ? cls.namespace + '.' : '') + cls.name + '.' + m.name }); }
      }
    }
    mmap.sort((a, b) => a.va.compare(b.va));
    const attr = (sp) => { let lo = 0, hi = mmap.length - 1, best = null;
      while (lo <= hi) { const mid = (lo + hi) >> 1;
        if (mmap[mid].va.compare(sp) <= 0) { best = mmap[mid]; lo = mid + 1; } else hi = mid - 1; }
      return best; };
    const out = { methods: mmap.length, lookups: [] };
    for (const a of addrs) {
      const p = ptr(a.startsWith('0x') ? a : '0x' + a);
      const e = attr(p);
      out.lookups.push({ addr: a,
        name: e ? e.name : '?',
        va: e ? '0x' + e.va.toString(16) : null,
        delta: e ? (parseInt(p.toString(16), 16) - parseInt(e.va.toString(16), 16)) : null });
    }
    out.elapsedSec = ((Date.now() - t0) / 1000).toFixed(1);
    return JSON.stringify(out);
  });
};

// whowrites(dispHex): find every instruction that references a given structure
// displacement (e.g. 0x798) and name the method containing it. A 4-byte
// displacement pattern is specific enough that chance matches are negligible, so
// the hits are real accesses - reads and writes alike - and the method names say
// which code sets a flag.
rpc.exports.whowrites = function (dispStr) {
  return Il2Cpp.perform(() => {
    const t0 = Date.now();
    const disp = parseInt(String(dispStr).replace(/^0x/, ''), 16) >>> 0;
    const b = [disp & 0xff, (disp >> 8) & 0xff, (disp >> 16) & 0xff, (disp >>> 24) & 0xff];
    const pat = b.map(x => x.toString(16).padStart(2, '0')).join(' ');
    const mod = Process.getModuleByName('GameAssembly.dll');
    const xr = moduleCodeRanges(mod);
    const out = { disp: '0x' + disp.toString(16), pattern: pat, hits: [], methods: [] };
    const addrs = [];
    for (const r of xr) {
      let hs; try { hs = Memory.scanSync(r.base, r.size, pat); } catch (e) { continue; }
      for (const h of hs) {
        if (out.hits.length >= 60) break;
        let ctx = '';
        try {
          const s2 = h.address.sub(16);
          const buf = new Uint8Array(s2.readByteArray(48));
          for (const x of buf) ctx += x.toString(16).padStart(2, '0');
        } catch (e) {}
        out.hits.push({ site: '0x' + h.address.toString(16), ctx: ctx });
        addrs.push(h.address);
      }
    }
    // name the containing method for each hit
    const mmap = [];
    for (const asm of Il2Cpp.domain.assemblies) {
      let img, classes;
      try { img = asm.image; } catch (e) { continue; }
      try { classes = img.classes; } catch (e) { continue; }
      for (const cls of classes) {
        let ms; try { ms = cls.methods; } catch (e) { ms = []; }
        for (const m of ms) { let va; try { va = m.virtualAddress; } catch (e) { continue; }
          if (!va.isNull()) mmap.push({ va: va, name: (cls.namespace ? cls.namespace + '.' : '') + cls.name + '.' + m.name }); }
      }
    }
    mmap.sort((a, b2) => a.va.compare(b2.va));
    const attr = (sp) => { let lo = 0, hi = mmap.length - 1, best = null;
      while (lo <= hi) { const mid = (lo + hi) >> 1;
        if (mmap[mid].va.compare(sp) <= 0) { best = mmap[mid]; lo = mid + 1; } else hi = mid - 1; }
      return best; };
    for (let i = 0; i < out.hits.length; i++) {
      const e = attr(addrs[i]);
      out.hits[i].inMethod = e ? e.name + ' @ 0x' + e.va.toString(16) : '?';
      out.hits[i].delta = e ? (parseInt(addrs[i].toString(16), 16) - parseInt(e.va.toString(16), 16)) : null;
    }
    out.methods = [...new Set(out.hits.map(h => h.inMethod))];
    out.elapsedSec = ((Date.now() - t0) / 1000).toFixed(1);
    return JSON.stringify(out);
  });
};
