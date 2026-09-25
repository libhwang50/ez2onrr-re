// _rating_recon.js — read-only helpers for the rating reverse-engineering.
//   fields(asm, names)   -> fields (name/type/static/offset) + method names
//   findType(asm, sub)   -> every class with a field/return type matching `sub`
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }

function typeName(f) { try { return '' + f.type.name; } catch (e) { return '?'; } }

rpc.exports.fields = function (asmName, names) {
  return onMain(() => {
    const img = Il2Cpp.domain.assembly(asmName).image;
    const out = {};
    const walk = (k, d) => {
      if (names.indexOf(k.name) >= 0) {
        const fs = [];
        try {
          for (const f of k.fields) {
            fs.push({ name: f.name, type: typeName(f),
                      stat: (() => { try { return f.isStatic; } catch (e) { return null; } })(),
                      off: (() => { try { return f.offset; } catch (e) { return null; } })() });
          }
        } catch (e) {}
        const ms = [];
        try { for (const m of k.methods) ms.push(m.name + '/' + m.parameterCount); } catch (e) {}
        out[k.name] = { fields: fs, methods: ms };
      }
      if (d > 0) { try { for (const n of k.nestedClasses) walk(n, d - 1); } catch (e) {} }
    };
    for (const k of img.classes) walk(k, 1);
    return out;
  });
};

rpc.exports.find = function (asmName, sub) {
  return onMain(() => {
    const q = ('' + sub).toLowerCase();
    const img = Il2Cpp.domain.assembly(asmName).image;
    const out = [];
    const scan = (k, d) => {
      const refs = [];
      if (('' + k.name).toLowerCase().indexOf(q) >= 0) refs.push('class ' + k.name);
      try {
        for (const f of k.fields) {
          if (('' + f.name).toLowerCase().indexOf(q) >= 0) refs.push('field ' + f.name + ':' + typeName(f));
        }
      } catch (e) {}
      try {
        for (const m of k.methods) {
          if (('' + m.name).toLowerCase().indexOf(q) >= 0) refs.push('method ' + m.name + '/' + m.parameterCount);
        }
      } catch (e) {}
      if (refs.length) out.push({ cls: k.name, refs: refs.slice(0, 30) });
      if (d > 0) { try { for (const n of k.nestedClasses) scan(n, d - 1); } catch (e) {} }
    };
    for (const k of img.classes) scan(k, 1);
    return out;
  });
};

// Dump the raw bytes of every method of a class (one RPC) so an offline
// disassembler can look for static-field references.
rpc.exports.dumpMethods = function (asmName, clsName, maxBytes) {
  return onMain(() => {
    const img = Il2Cpp.domain.assembly(asmName).image;
    let k = null;
    const walk = (c, d) => { if (!k && c.name === clsName) k = c;
      if (d > 0) { try { for (const n of c.nestedClasses) walk(n, d - 1); } catch (e) {} } };
    for (const c of img.classes) walk(c, 1);
    if (!k) return { err: 'no class' };
    const ms = [];
    try {
      for (const m of k.methods) {
        let a; try { a = m.virtualAddress; } catch (e) { continue; }
        if (a.isNull()) continue;
        ms.push({ name: m.name + '/' + m.parameterCount, va: Number(a.toString()) });
      }
    } catch (e) { return { err: 'methods: ' + e }; }
    ms.sort((x, y) => x.va - y.va);
    const out = [];
    for (let i = 0; i < ms.length; i++) {
      const size = Math.min((i + 1 < ms.length ? ms[i + 1].va - ms[i].va : 0x200),
                            maxBytes || 0x1000);
      if (size <= 0 || size > (maxBytes || 0x1000)) continue;
      let hex = null;
      try {
        const u = new Uint8Array(ptr(ms[i].va).readByteArray(size));
        hex = Array.from(u).map(b => b.toString(16).padStart(2, '0')).join('');
      } catch (e) {}
      out.push({ name: ms[i].name, va: ms[i].va, size: size, hex: hex });
    }
    return out;
  });
};

// Find methods whose parameter types match `sub`.
rpc.exports.findParams = function (asmName, sub) {
  return onMain(() => {
    const img = Il2Cpp.domain.assembly(asmName).image;
    const out = [];
    const scan = (k, d) => {
      const refs = [];
      try {
        for (const m of k.methods) {
          let ps = [];
          try { ps = m.parameters; } catch (e) { ps = []; }
          for (let i = 0; i < ps.length; i++) {
            let t = '';
            try { t = '' + ps[i].type.name; } catch (e) { continue; }
            if (t.indexOf(sub) >= 0) refs.push(m.name + '/' + m.parameterCount + ' param' + i + ':' + t);
          }
        }
      } catch (e) {}
      if (refs.length) out.push({ cls: k.name, refs: refs.slice(0, 30) });
      if (d > 0) { try { for (const n of k.nestedClasses) scan(n, d - 1); } catch (e) {} }
    };
    for (const k of img.classes) scan(k, 1);
    return out;
  });
};

rpc.exports.findType = function (asmName, sub) {
  return onMain(() => {
    const img = Il2Cpp.domain.assembly(asmName).image;
    const out = [];
    const scan = (k, d) => {
      const refs = [];
      try {
        for (const f of k.fields) {
          const t = typeName(f);
          if (t.indexOf(sub) >= 0) refs.push('field ' + f.name + ':' + t
            + ((() => { try { return f.isStatic ? ' static@' + f.offset : ''; } catch (e) { return ''; } })()));
        }
      } catch (e) {}
      try {
        for (const m of k.methods) {
          let r = '';
          try { r = '' + m.returnType.name; } catch (e) { r = ''; }
          if (r.indexOf(sub) >= 0) refs.push('ret ' + m.name + ' -> ' + r);
        }
      } catch (e) {}
      if (refs.length) out.push({ cls: k.name, refs: refs.slice(0, 25) });
      if (d > 0) { try { for (const n of k.nestedClasses) scan(n, d - 1); } catch (e) {} }
    };
    for (const k of img.classes) scan(k, 1);
    return out;
  });
};
