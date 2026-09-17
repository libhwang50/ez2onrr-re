const mod = Process.getModuleByName("GameAssembly.dll");
const E = n => mod.getExportByName(n);
const D = new NativeFunction(E("il2cpp_domain_get"), 'pointer', []);
const A = new NativeFunction(E("il2cpp_domain_get_assemblies"), 'pointer', ['pointer', 'pointer']);
const I = new NativeFunction(E("il2cpp_assembly_get_image"), 'pointer', ['pointer']);
const IN = new NativeFunction(E("il2cpp_image_get_name"), 'pointer', ['pointer']);
const CC = new NativeFunction(E("il2cpp_image_get_class_count"), 'uint32', ['pointer']);
const CL = new NativeFunction(E("il2cpp_image_get_class"), 'pointer', ['pointer', 'uint32']);
const CN = new NativeFunction(E("il2cpp_class_get_name"), 'pointer', ['pointer']);
const CNS = new NativeFunction(E("il2cpp_class_get_namespace"), 'pointer', ['pointer']);
const FL = new NativeFunction(E("il2cpp_class_get_fields"), 'pointer', ['pointer', 'pointer']);
const FN = new NativeFunction(E("il2cpp_field_get_name"), 'pointer', ['pointer']);
const FO = new NativeFunction(E("il2cpp_field_get_offset"), 'uint32', ['pointer']);
const FT = new NativeFunction(E("il2cpp_field_get_type"), 'pointer', ['pointer']);
const TN = new NativeFunction(E("il2cpp_type_get_name"), 'pointer', ['pointer']);
const FSF = new NativeFunction(E("il2cpp_field_get_flags"), 'uint32', ['pointer']);
const FSV = new NativeFunction(E("il2cpp_field_static_get_value"), 'void', ['pointer', 'pointer']);
const SC = new NativeFunction(E("il2cpp_string_chars"), 'pointer', ['pointer']);
const SL = new NativeFunction(E("il2cpp_string_length"), 'int32', ['pointer']);

function RS(p) {
  if (!p || p.isNull()) return null;
  try { const l = SL(p); if (l <= 0 || l > 20000) return null; return SC(p).readUtf16String(l); } catch (e) { return null; }
}

rpc.exports.run = function () {
  const out = { tcp2025: [], vxRefs: [] };
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
      let cn; try { cn = CN(k).readUtf8String(); } catch (e) { continue; }
      let cns = ""; try { cns = CNS(k).readUtf8String(); } catch (e) {}
      // collect TCP2025* classes + their static string fields
      if (cns.indexOf("TCP2025") >= 0 || cn === "AesManager" || cn === "AesKeyJson" || cn === "RsaManager") {
        let it = Memory.alloc(Process.pointerSize); it.writePointer(NULL);
        let fld;
        const fs = [];
        while (!(fld = FL(k, it)).isNull()) {
          const fn = FN(fld).readUtf8String();
          let t = null; try { t = TN(FT(fld)).readUtf8String(); } catch (e) {}
          let flags = 0; try { flags = FSF(fld); } catch (e) {}
          let val = null;
          if ((flags & 0x10) && t === "System.String") {
            const vp = Memory.alloc(Process.pointerSize);
            try { FSV(fld, vp); val = RS(vp.readPointer()); } catch (e) {}
          }
          fs.push({ name: fn, type: t, static: (flags & 0x10) !== 0, val: val });
        }
        out.tcp2025.push({ ns: cns, cls: cn, fields: fs });
      }
      // find fields whose type references vx / wy / zf.wx
      let it2 = Memory.alloc(Process.pointerSize); it2.writePointer(NULL);
      let fld2;
      while (!(fld2 = FL(k, it2)).isNull()) {
        const fn = FN(fld2).readUtf8String();
        let t = null; try { t = TN(FT(fld2)).readUtf8String(); } catch (e) {}
        if (t && (t === "vx" || t.indexOf("vx") >= 0 || t.indexOf("List<vx") >= 0)) {
          let flags = 0; try { flags = FSF(fld2); } catch (e) {}
          out.vxRefs.push({ ns: cns, cls: cn, field: fn, type: t, static: (flags & 0x10) !== 0, off: FO(fld2) });
        }
      }
    }
  }
  return out;
};
