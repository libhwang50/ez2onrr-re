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
const FT = new NativeFunction(E("il2cpp_field_get_type"), 'pointer', ['pointer']);
const TN = new NativeFunction(E("il2cpp_type_get_name"), 'pointer', ['pointer']);
const FSF = new NativeFunction(E("il2cpp_field_get_flags"), 'uint32', ['pointer']);
const FSV = new NativeFunction(E("il2cpp_field_static_get_value"), 'void', ['pointer', 'pointer']);
const SC = new NativeFunction(E("il2cpp_string_chars"), 'pointer', ['pointer']);
const SL = new NativeFunction(E("il2cpp_string_length"), 'int32', ['pointer']);

function RS(p) { if (!p || p.isNull()) return null; try { const l = SL(p); if (l <= 0 || l > 4000) return null; return SC(p).readUtf16String(l); } catch (e) { return null; } }

function arrInfo(p) {
  if (!p || p.isNull()) return null;
  try { return { len: Number(p.add(0x18).readS64().toString()), data: p.add(0x20) }; } catch (e) { return null; }
}

const SBOX_HEAD = [0x63, 0x7c, 0x77, 0x7b];

rpc.exports.probe = function () {
  const hits = [];
  const dom = D(), sp = Memory.alloc(8);
  const asms = A(dom, sp), n = Number(sp.readU64().toString());
  for (let i = 0; i < n; i++) {
    let img; try { img = I(asms.add(i * Process.pointerSize).readPointer()); } catch (e) { continue; }
    let nm; try { nm = IN(img).readUtf8String(); } catch (e) { continue; }
    const cnt = CC(img);
    for (let c = 0; c < cnt; c++) {
      let k; try { k = CL(img, c); } catch (e) { continue; }
      if (k.isNull()) continue;
      let cn; try { cn = CN(k).readUtf8String(); } catch (e) { continue; }
      let cns = ""; try { cns = CNS(k).readUtf8String(); } catch (e) {}
      // only inspect classes whose name suggests crypto OR any class (cheap enough)
      let it = Memory.alloc(Process.pointerSize); it.writePointer(NULL);
      let fld;
      while (!(fld = FL(k, it)).isNull()) {
        let flags = 0; try { flags = FSF(fld); } catch (e) { continue; }
        if ((flags & 0x10) === 0) continue; // static only
        let t = null; try { t = TN(FT(fld)).readUtf8String(); } catch (e) {}
        if (!t || t.indexOf("System.Byte[]") < 0) continue;
        const vp = Memory.alloc(Process.pointerSize);
        try { FSV(fld, vp); } catch (e) { continue; }
        const ai = arrInfo(vp.readPointer());
        if (!ai || ai.len !== 256) continue;
        let head;
        try { head = new Uint8Array(ai.data.readByteArray(4)); } catch (e) { continue; }
        if (head[0] === 0x63 && head[1] === 0x7c && head[2] === 0x77 && head[3] === 0x7b) {
          let fn = ""; try { fn = FN(fld).readUtf8String(); } catch (e) {}
          hits.push({ image: nm, ns: cns, cls: cn, field: fn, len: ai.len });
        }
      }
    }
  }
  return hits;
};
