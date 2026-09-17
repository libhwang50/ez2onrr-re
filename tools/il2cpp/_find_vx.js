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
  try { const l = SL(p); if (l <= 0 || l > 20000) return null; return SC(p).readUtf16String(l); } catch (e) { return null; }
}

rpc.exports.findVx = function () {
  // locate vx klass
  let vxKlass = null;
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
      if (CN(k).readUtf8String() === "vx") { vxKlass = k; break; }
    }
    if (vxKlass) break;
  }
  if (!vxKlass) return { error: "vx class not found" };

  // field offsets
  const offs = {};
  let it = Memory.alloc(Process.pointerSize); it.writePointer(NULL);
  let fld;
  while (!(fld = FL(vxKlass, it)).isNull()) {
    const fn = FN(fld).readUtf8String();
    let t = null; try { t = TN(FT(fld)).readUtf8String(); } catch (e) {}
    offs[fn] = { off: FO(fld), type: t };
  }

  const pat = Array.from(new Uint8Array(vxKlass.readByteArray(8))).map(b => b.toString(16).padStart(2, '0')).join(' ');
  const found = [];
  const ranges = Process.enumerateRanges('rw-');
  for (const r of ranges) {
    if (r.size < 64) continue;
    if (r.size > 256 * 1024 * 1024) continue;
    let m; try { m = Memory.scanSync(r.base, r.size, pat); } catch (e) { continue; }
    for (const x of m) {
      const a = x.address;
      const rec = { address: a.toString(), fields: {} };
      for (const name in offs) {
        const o = offs[name];
        if (o.off <= 0) continue;
        try {
          if ((o.type || "").indexOf("System.String") >= 0) {
            rec.fields[name] = RS(a.add(o.off).readPointer());
          } else if (o.type === "System.Int32") {
            rec.fields[name] = a.add(o.off).readS32();
          }
        } catch (e) {}
      }
      found.push(rec);
      if (found.length >= 200) return { vxKlass: vxKlass.toString(), offs: offs, found: found };
    }
  }
  return { vxKlass: vxKlass.toString(), offs: offs, found: found };
};
