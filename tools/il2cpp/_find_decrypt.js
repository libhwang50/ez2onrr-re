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
const CM = new NativeFunction(E("il2cpp_class_get_methods"), 'pointer', ['pointer', 'pointer']);
const MN = new NativeFunction(E("il2cpp_method_get_name"), 'pointer', ['pointer']);
const MPC = new NativeFunction(E("il2cpp_method_get_param_count"), 'uint32', ['pointer']);
const MP = new NativeFunction(E("il2cpp_method_get_param"), 'pointer', ['pointer', 'uint32']);
const MRT = new NativeFunction(E("il2cpp_method_get_return_type"), 'pointer', ['pointer']);
const MF = new NativeFunction(E("il2cpp_method_get_flags"), 'uint32', ['pointer', 'pointer']);
const CT = new NativeFunction(E("il2cpp_class_from_type"), 'pointer', ['pointer']);
const TYPEN = new NativeFunction(E("il2cpp_type_get_name"), 'pointer', ['pointer']);
const MC = new NativeFunction(E("il2cpp_method_get_class"), 'pointer', ['pointer']);

function tname(t) { if (!t || t.isNull()) return null; try { return TYPEN(t).readUtf8String(); } catch (e) { return null; } }

rpc.exports.run = function () {
  const out = [];
  const dom = D(), sp = Memory.alloc(8);
  const asms = A(dom, sp), n = Number(sp.readU64().toString());
  for (let i = 0; i < n; i++) {
    let img; try { img = I(asms.add(i * Process.pointerSize).readPointer()); } catch (e) { continue; }
    let nm; try { nm = IN(img).readUtf8String(); } catch (e) { continue; }
    if (nm !== "Assembly-CSharp.dll") continue;
    const cnt = CC(img);
    for (let c = 0; c < cnt; c++) {
      let k; try { k = CL(img, c); } catch (e) { continue; }
      if (k.isNull()) continue;
      let cn; try { cn = CN(k).readUtf8String(); } catch (e) { continue; }
      let it = Memory.alloc(Process.pointerSize); it.writePointer(NULL);
      let m;
      while (!(m = CM(k, it)).isNull()) {
        let rt = null; try { rt = tname(MRT(m)); } catch (e) {}
        if (!rt || rt.indexOf("System.Byte[]") < 0) continue;
        let pn; try { pn = MPC(m); } catch (e) { pn = 0; }
        if (pn > 4) continue;
        const ps = [];
        for (let p = 0; p < pn; p++) ps.push(tname(MP(m, p)));
        let flags = 0; let fptr = Memory.alloc(4); try { flags = MF(m, fptr); } catch (e) {}
        let mn = ''; try { mn = MN(m).readUtf8String(); } catch (e) {}
        out.push({ cls: cn, method: mn, params: ps, statik: (flags & 0x10) !== 0, ptr: m.readPointer().toString() });
        if (out.length >= 400) return out;
      }
    }
  }
  return out;
};
