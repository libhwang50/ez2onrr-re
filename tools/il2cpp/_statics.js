// _statics.js — list static fields of a class with static-region offset, type and
// (for Byte[]) live length + head bytes.  Read-only.
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
function hex(p, n) {
  const u = new Uint8Array(p.readByteArray(n));
  let h = ''; for (let i = 0; i < u.length; i++) h += u[i].toString(16).padStart(2, '0');
  return h;
}

rpc.exports.statics = function (asmName, clsName) {
  return onMain(() => {
    const img = Il2Cpp.domain.assembly(asmName).image;
    let k = null;
    for (const c of img.classes) if (c.name === clsName) { k = c; break; }
    if (!k) return { err: 'no class' };
    const out = { klass: k.handle.toString(), fields: [] };
    let sf = null;
    try { sf = k.handle.add(0xb8).readPointer(); } catch (e) {}
    out.staticFields = sf ? sf.toString() : null;
    for (const f of k.fields) {
      if (!f.isStatic) continue;
      const rec = { name: f.name };
      try { rec.type = '' + f.type.name; } catch (e) { rec.type = '?'; }
      try { rec.offset = f.offset; } catch (e) { rec.offset = null; }
      if (sf && typeof rec.offset === 'number') {
        try {
          const p = sf.add(rec.offset).readPointer();
          rec.ptr = p.toString();
          if (!p.isNull()) {
            const len = p.add(0x18).readS32();
            if (len > 0 && len < 100000) {
              rec.arrLen = len;
              rec.head = hex(p.add(0x20), Math.min(len, 48));
            }
          }
        } catch (e) { rec.err = '' + e; }
      }
      out.fields.push(rec);
    }
    out.fields.sort((a, b) => (a.offset || 0) - (b.offset || 0));
    return out;
  });
};
