const mod = Process.getModuleByName("GameAssembly.dll");
const E = n => mod.getExportByName(n);
const D = new NativeFunction(E("il2cpp_domain_get"), 'pointer', []);
const A = new NativeFunction(E("il2cpp_domain_get_assemblies"), 'pointer', ['pointer', 'pointer']);
const I = new NativeFunction(E("il2cpp_assembly_get_image"), 'pointer', ['pointer']);
const IN = new NativeFunction(E("il2cpp_image_get_name"), 'pointer', ['pointer']);
const CC = new NativeFunction(E("il2cpp_image_get_class_count"), 'uint32', ['pointer']);
const CL = new NativeFunction(E("il2cpp_image_get_class"), 'pointer', ['pointer', 'uint32']);
const CN = new NativeFunction(E("il2cpp_class_get_name"), 'pointer', ['pointer']);
const FL = new NativeFunction(E("il2cpp_class_get_fields"), 'pointer', ['pointer', 'pointer']);
const FN = new NativeFunction(E("il2cpp_field_get_name"), 'pointer', ['pointer']);
const FO = new NativeFunction(E("il2cpp_field_get_offset"), 'uint32', ['pointer']);
const FT = new NativeFunction(E("il2cpp_field_get_type"), 'pointer', ['pointer']);
const TN = new NativeFunction(E("il2cpp_type_get_name"), 'pointer', ['pointer']);
const FSF = new NativeFunction(E("il2cpp_field_get_flags"), 'uint32', ['pointer']);
const FSV = new NativeFunction(E("il2cpp_field_static_get_value"), 'void', ['pointer', 'pointer']);
const SC = new NativeFunction(E("il2cpp_string_chars"), 'pointer', ['pointer']);
const SL = new NativeFunction(E("il2cpp_string_length"), 'int32', ['pointer']);

const STATIC_FLAG = 0x10;

function RS(p) {
  if (!p || p.isNull()) return null;
  try { const l = SL(p); if (l <= 0 || l > 40000) return null; return SC(p).readUtf16String(l); } catch (e) { return null; }
}
function readByteArray(p, maxlen) {
  if (!p || p.isNull()) return null;
  try {
    const l = Number(p.add(0x18).readS64().toString());
    if (l <= 0 || l > maxlen) return null;
    const bytes = new Uint8Array(p.add(0x20).readByteArray(l));
    let hex = ''; for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
    return { len: l, hex: hex };
  } catch (e) { return null; }
}
function hex(b) { if (!b) return null; let s = ''; for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0'); return s; }

function findInGameCore() {
  const dom = D(), sp = Memory.alloc(8);
  const asms = A(dom, sp), n = Number(sp.readU64().toString());
  for (let i = 0; i < n; i++) {
    let img; try { img = I(asms.add(i * Process.pointerSize).readPointer()); } catch (e) { continue; }
    let nm; try { nm = IN(img).readUtf8String(); } catch (e) { continue; }
    if (nm !== "Assembly-CSharp.dll") continue;
    const cnt = CC(img);
    for (let c = 0; c < cnt; c++) {
      const k = CL(img, c);
      if (k.isNull()) continue;
      if (CN(k).readUtf8String() !== "InGameCore") continue;
      let it = Memory.alloc(Process.pointerSize); it.writePointer(NULL);
      let fld, instField = null;
      const flds = [];
      while (!(fld = FL(k, it)).isNull()) {
        const fname = FN(fld).readUtf8String();
        let t = null; try { t = TN(FT(fld)).readUtf8String(); } catch (e) {}
        let flags = 0; try { flags = FSF(fld); } catch (e) {}
        flds.push({ name: fname, off: FO(fld), type: t, field: fld, isStatic: (flags & STATIC_FLAG) !== 0 });
        if (fname === "instance") instField = fld;
      }
      if (!instField) return { error: "no instance field" };
      const vp = Memory.alloc(Process.pointerSize);
      FSV(instField, vp);
      const o = vp.readPointer();
      if (o.isNull()) return { error: "instance null" };
      return { o: o, flds: flds };
    }
  }
  return { error: "InGameCore not found" };
}

rpc.exports.run = function () {
  const f = findInGameCore();
  if (f.error) return f;
  const o = f.o;
  const out = { instance: o.toString(), strings: {}, bytearrays: {}, ints: {}, bools: {}, statics: {} };
  for (const fd of f.flds) {
    if (fd.off <= 0) continue;
    try {
      const t = fd.type || "";
      if (fd.isStatic) {
        const vp = Memory.alloc(Process.pointerSize);
        FSV(fd.field, vp);
        const p = vp.readPointer();
        if (t.indexOf("System.String") >= 0 && t.indexOf("[]") < 0) {
          const s = RS(p);
          if (s) out.statics[fd.name] = { type: t, str: s };
        } else if (t.indexOf("System.Byte[]") >= 0) {
          const b = readByteArray(p, 4 * 1024 * 1024);
          if (b) out.statics[fd.name] = { type: t, len: b.len, hex: b.hex };
        } else if (t === "System.Int32") {
          out.statics[fd.name] = { type: t, i: vp.readS32() };
        }
        continue;
      }
      // instance fields
      if (t.indexOf("System.String") >= 0 && t.indexOf("[]") < 0) {
        const s = RS(o.add(fd.off).readPointer());
        if (s) out.strings[fd.name] = s;
      } else if (t.indexOf("System.Byte[]") >= 0) {
        const b = readByteArray(o.add(fd.off).readPointer(), 4 * 1024 * 1024);
        if (b) out.bytearrays[fd.name] = b;
      } else if (t === "System.Int32") {
        out.ints[fd.name] = o.add(fd.off).readS32();
      } else if (t === "System.Boolean") {
        out.bools[fd.name] = o.add(fd.off).readU8() !== 0;
      }
    } catch (e) {}
  }
  return out;
};

rpc.exports.scanEzff = function () {
  const results = [];
  const ranges = Process.enumerateRanges('rw-');
  for (const r of ranges) {
    if (r.size < 0x4000) continue;
    if (r.size > 512 * 1024 * 1024) continue;
    let matches;
    try { matches = Memory.scanSync(r.base, r.size, "45 5a 46 46"); } catch (e) { continue; }
    for (const m of matches) {
      const a = m.address;
      const avail = r.size - (Number(a.toString()) - Number(r.base.toString()));
      const n = Math.min(160, avail);
      results.push({ address: a.toString(), ctx: hex(new Uint8Array(a.readByteArray(n))) });
      if (results.length >= 40) return results;
    }
  }
  return results;
};
