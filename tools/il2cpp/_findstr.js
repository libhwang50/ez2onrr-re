// _findstr.js — find a managed string in memory and who holds it. Read-only.
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }

function utf16hex(s) {
  let h = ''; for (const ch of s) { const c = ch.charCodeAt(0); h += (c & 0xff).toString(16).padStart(2, '0') + ((c >> 8) & 0xff).toString(16).padStart(2, '0'); }
  return h;
}
function asciihex(s) {
  let h = ''; for (let i = 0; i < s.length; i++) h += s.charCodeAt(i).toString(16).padStart(2, '0');
  return h;
}

// Scan readable ranges for a pattern, returning the raw hit addresses and which form matched.
rpc.exports.scan = function (needle, limit) {
  const forms = [['utf16', utf16hex(needle)], ['ascii', asciihex(needle)]];
  const hits = [];
  const ranges = Process.enumerateRanges({ protection: 'r--', coalesce: true })
    .concat(Process.enumerateRanges({ protection: 'rw-', coalesce: true }));
  for (const r of ranges) {
    if (r.size < 64) continue;
    for (const [form, hexp] of forms) {
      const pat = hexp.match(/../g).join(' ');
      try {
        for (const m of Memory.scanSync(r.base, r.size, pat)) {
          hits.push({ addr: m.address.toString(), form: form, size: r.size });
          if (hits.length >= (limit || 200)) return hits;
        }
      } catch (e) {}
    }
  }
  return hits;
};

// Given the address of the first character, describe the Il2CppString around it.
// Handles both the UTF-16 managed form and an ASCII byte string.
rpc.exports.strAt = function (charAddr) {
  const out = {};
  for (const back of [0x14, 0x10, 0x0c, 0x18, 0x1c]) {
    try {
      const base = ptr(charAddr).sub(back);
      const len = base.add(0x10).readS32();
      if (len <= 0 || len > 512) continue;
      out['back' + back.toString(16)] = {
        base: base.toString(), len: len, klass: base.readPointer().toString(),
        utf16: base.add(0x14).readUtf16String(Math.min(len, 200)),
        ascii: (() => { try { return base.add(0x14).readUtf8String(Math.min(len, 200)); } catch (e) { return null; } })()
      };
    } catch (e) {}
  }
  // also describe an ASCII literal sitting at charAddr (no managed header)
  try { out.asciiAtAddr = ptr(charAddr).readUtf8String(64); } catch (e) {}
  return out;
};

// What is the class name of an object pointer?
rpc.exports.klassName = function (objAddr, back) {
  try {
    const base = ptr(objAddr).sub(back === undefined ? 0 : back);
    const kl = base.readPointer();
    const nm = kl.add(0x10).readPointer().readUtf8String();
    const ns = kl.add(0x18).readPointer().readUtf8String();
    return { klass: kl.toString(), name: nm, ns: ns };
  } catch (e) { return { err: '' + e }; }
};

// Enumerate every class field whose name or value mentions a needle.
rpc.exports.fields = function (needle) {
  return onMain(() => {
    const out = [];
    const low = needle.toLowerCase();
    for (const asm of Il2Cpp.domain.assemblies) {
      let img; try { img = asm.image; } catch (e) { continue; }
      const walk = (k, depth) => {
        try {
          for (const f of k.fields) {
            if (f.name.toLowerCase().indexOf(low) >= 0) {
              out.push({ cls: k.name, field: f.name, static: !!f.isStatic, type: '' + f.type.name });
            }
          }
        } catch (e) {}
        if (depth > 0) { try { for (const n of k.nestedClasses) walk(n, depth - 1); } catch (e) {} }
      };
      for (const k of img.classes) walk(k, 1);
    }
    return out;
  });
};

// Find the c2s_get_pattern_file request JSON the game holds as a UTF-16 string.
// It carries musicresourcename / keymode / levelmode / gamemode for the chart in play.
rpc.exports.patternjson = function () {
  // '{"appid":"' in UTF-16LE
  const pat = '7b 00 22 00 61 00 70 00 70 00 69 00 64 00 22 00 3a 00 22 00';
  const out = [];
  const ranges = Process.enumerateRanges({ protection: 'rw-', coalesce: true });
  for (const r of ranges) {
    if (r.size < 64 || r.size > 512 * 1024 * 1024) continue;
    try {
      for (const m of Memory.scanSync(r.base, r.size, pat)) {
        try {
          const s = m.address.readUtf16String(400);
          if (s && s.indexOf('musicresourcename') >= 0) out.push(s.replace(/\u0000.*$/, ''));
        } catch (e) {}
      }
    } catch (e) {}
    if (out.length >= 40) break;
  }
  return out;
};
