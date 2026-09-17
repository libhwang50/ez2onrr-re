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
const FT = new NativeFunction(E("il2cpp_field_get_type"), 'pointer', ['pointer']);
const TN = new NativeFunction(E("il2cpp_type_get_name"), 'pointer', ['pointer']);
const FSF = new NativeFunction(E("il2cpp_field_get_flags"), 'uint32', ['pointer']);
const FSV = new NativeFunction(E("il2cpp_field_static_get_value"), 'void', ['pointer', 'pointer']);

rpc.exports.run = function () {
  const out = [];
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
      let it = Memory.alloc(Process.pointerSize); it.writePointer(NULL);
      let f;
      while (!(f = FL(k, it)).isNull()) {
        let flags = 0; try { flags = FSF(f); } catch (e) { continue; }
        if ((flags & 0x10) === 0) continue;
        let t = null; try { t = TN(FT(f)).readUtf8String(); } catch (e) {}
        if (!t || (t.indexOf('System.Byte[]') < 0 && t.indexOf('System.SByte[]') < 0)) continue;
        const vp = Memory.alloc(Process.pointerSize);
        try { FSV(f, vp); } catch (e) { continue; }
        const arr = vp.readPointer();
        if (!arr || arr.isNull()) continue;
        let len; try { len = Number(arr.add(0x18).readS64().toString()); } catch (e) { continue; }
        if (len < 16 || len > 64) continue;
        let hex = null;
        try { const b = new Uint8Array(arr.add(0x20).readByteArray(len)); let s = ''; for (let j = 0; j < b.length; j++) s += b[j].toString(16).padStart(2, '0'); hex = s; } catch (e) { continue; }
        out.push({ image: nm, cls: cn, field: FN(f).readUtf8String(), len: len, hex: hex });
      }
    }
  }
  return out;
};
