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
const SC = new NativeFunction(E("il2cpp_string_chars"), 'pointer', ['pointer']);
const SL = new NativeFunction(E("il2cpp_string_length"), 'int32', ['pointer']);

function RS(p) {
  if (!p || p.isNull()) return null;
  try {
    const l = SL(p);
    if (l <= 0 || l > 4000) return null;
    const s = SC(p).readUtf16String(l);
    // reject strings with control chars
    for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); if (c < 9 || (c > 13 && c < 32)) return null; }
    return s;
  } catch (e) { return null; }
}

function findClass(name) {
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
      if (CN(k).readUtf8String() === name) return k;
    }
  }
  return null;
}

rpc.exports.findWy = function () {
  const k = findClass("wy");
  if (!k) return { error: "wy not found" };
  const pat = Array.from(new Uint8Array(k.readByteArray(8))).map(b => b.toString(16).padStart(2, '0')).join(' ');
  const results = [];
  const ranges = Process.enumerateRanges('rw-');
  for (const r of ranges) {
    if (r.size < 64) continue;
    if (r.size > 256 * 1024 * 1024) continue;
    let m; try { m = Memory.scanSync(r.base, r.size, pat); } catch (e) { continue; }
    for (const x of m) {
      const a = x.address;
      let u1 = null, u2 = null, bk = null, res = null;
      try { u1 = RS(a.add(0x10).readPointer()); } catch (e) {}
      try { u2 = RS(a.add(0x18).readPointer()); } catch (e) {}
      try { bk = RS(a.add(0x20).readPointer()); } catch (e) {}
      try { res = a.add(0x28).readS32(); } catch (e) {}
      // only keep candidates with at least one real-looking url/key
      const isUrl = (s) => s && (s.indexOf("http") === 0 || s.indexOf("ez2game") >= 0);
      const isKey = (s) => s && s.length >= 8 && /^[0-9a-fA-F]+$/.test(s);
      if (isUrl(u1) || isUrl(u2) || isKey(bk)) {
        results.push({ address: a.toString(), final_url_ez: u1 ? u1.slice(0, 80) : null, final_url_ezi: u2 ? u2.slice(0, 80) : null, bundleCryptKey: bk, result: res });
      }
      if (results.length >= 50) return { klass: k.toString(), results: results };
    }
  }
  return { klass: k.toString(), results: results };
};
