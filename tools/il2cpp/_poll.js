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
function bytesHex(p, maxlen) {
  if (!p || p.isNull()) return null;
  try {
    const l = Number(p.add(0x18).readS64().toString());
    if (l <= 0 || l > maxlen) return null;
    const b = new Uint8Array(p.add(0x20).readByteArray(l));
    let s = ''; for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
    return s;
  } catch (e) { return null; }
}
function listCount(p) {
  if (!p || p.isNull()) return -1;
  try { return p.add(0x18).readS32(); } catch (e) { return -1; }
}

let CACHE = null;
function getIGC() {
  if (CACHE) return CACHE;
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
      const offs = {};
      while (!(fld = FL(k, it)).isNull()) {
        const fname = FN(fld).readUtf8String();
        let t = null; try { t = TN(FT(fld)).readUtf8String(); } catch (e) {}
        let flags = 0; try { flags = FSF(fld); } catch (e) {}
        offs[fname] = { off: FO(fld), type: t, field: fld, isStatic: (flags & STATIC_FLAG) !== 0 };
        if (fname === "instance") instField = fld;
      }
      const vp = Memory.alloc(Process.pointerSize);
      FSV(instField, vp);
      const o = vp.readPointer();
      CACHE = { o: o, offs: offs };
      return CACHE;
    }
  }
  return null;
}

rpc.exports.state = function () {
  const g = getIGC();
  if (!g) return { error: "InGameCore not found" };
  const { o, offs } = g;
  const s = {};
  function str(name) { const f = offs[name]; if (!f || !o || o.isNull()) return null; return RS(o.add(f.off).readPointer()); }
  function ba(name, max) { const f = offs[name]; if (!f || !o || o.isNull()) return null; return bytesHex(o.add(f.off).readPointer(), max); }
  function lc(name) { const f = offs[name]; if (!f || !o || o.isNull()) return -1; return listCount(o.add(f.off).readPointer()); }
  function sb(name) { const f = offs[name]; if (!f || !o || o.isNull()) return null; return o.add(f.off).readU8() !== 0; }
  // static byte arrays svk..svr
  const statics = {};
  for (const nm of ["svk", "svl", "svm", "svn", "svo", "svp", "svq", "svr"]) {
    const f = offs[nm];
    if (f && f.isStatic) {
      const vp = Memory.alloc(Process.pointerSize);
      try { FSV(f.field, vp); statics[nm] = bytesHex(vp.readPointer(), 1 << 20); } catch (e) { statics[nm] = null; }
    }
  }
  return {
    sol: str("sol"),
    ez_url: str("ez_url"),
    ezi_url: str("ezi_url"),
    bundleCryptKey: ba("bundleCryptKey", 1 << 20),
    ReadyToURL: sb("ReadyToURL"),
    svt: str("svt"),
    statics: statics,
    normalNoteData: lc("normalNoteData"),
    longNoteData: lc("longNoteData"),
    bpmNoteData: lc("bpmNoteData"),
    instrumentDic: lc("instrumentDic"),
    patternFileInfo: lc("patternFileInfo"),
  };
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
      const n = Math.min(256 * 1024, avail);
      const chunk = new Uint8Array(a.readByteArray(n));
      let hex = ''; for (let i = 0; i < chunk.length; i++) hex += chunk[i].toString(16).padStart(2, '0');
      results.push({ address: a.toString(), len: n, hex: hex });
      if (results.length >= 20) return results;
    }
  }
  return results;
};
