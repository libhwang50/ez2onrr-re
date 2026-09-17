const mod = Process.getModuleByName("GameAssembly.dll");
const MBASE = mod.base, MSIZE = mod.size;
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
const MNP = new NativeFunction(E("il2cpp_method_get_param_count"), 'uint32', ['pointer']);
const MNG = new NativeFunction(E("il2cpp_method_get_param_name"), 'pointer', ['pointer', 'uint32']);

function inModule(p) { try { const v = Number(p.toString()); const b = Number(MBASE.toString()); return v >= b && v < b + MSIZE; } catch (e) { return false; } }

rpc.exports.probe = function () {
  const out = [];
  const dom = D(), sp = Memory.alloc(8);
  const asms = A(dom, sp), n = Number(sp.readU64().toString());
  for (let i = 0; i < n; i++) {
    let img; try { img = I(asms.add(i * Process.pointerSize).readPointer()); } catch (e) { continue; }
    let nm; try { nm = IN(img).readUtf8String(); } catch (e) { continue; }
    if (nm !== "System.Core.dll") continue;
    const cnt = CC(img);
    for (let c = 0; c < cnt; c++) {
      const k = CL(img, c);
      if (k.isNull()) continue;
      let cn; try { cn = CN(k).readUtf8String(); } catch (e) { continue; }
      let cns = ""; try { cns = CNS(k).readUtf8String(); } catch (e) {}
      if (cn !== "AesTransform") continue;
      out.push({ cls: cns + "." + cn, klass: k.toString() });
      let it = Memory.alloc(Process.pointerSize); it.writePointer(NULL);
      let m;
      while (!(m = CM(k, it)).isNull()) {
        let mn = ""; try { mn = MN(m).readUtf8String(); } catch (e) {}
        let np = m.readPointer();
        out.push({ method: mn, ptr: np.toString(), inMod: inModule(np), mp0: m.readPointer().toString(), mp8: m.add(8).readPointer().toString(), mp16: m.add(16).readPointer().toString() });
      }
    }
  }
  return out;
};
