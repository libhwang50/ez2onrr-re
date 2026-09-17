const mod = Process.getModuleByName("GameAssembly.dll");
const E = n => mod.getExportByName(n);
const D = new NativeFunction(E("il2cpp_domain_get"), 'pointer', []);
const A = new NativeFunction(E("il2cpp_domain_get_assemblies"), 'pointer', ['pointer', 'pointer']);
const I = new NativeFunction(E("il2cpp_assembly_get_image"), 'pointer', ['pointer']);
const IN = new NativeFunction(E("il2cpp_image_get_name"), 'pointer', ['pointer']);
const CM = new NativeFunction(E("il2cpp_class_get_methods"), 'pointer', ['pointer', 'pointer']);
const MN = new NativeFunction(E("il2cpp_method_get_name"), 'pointer', ['pointer']);
const MPC = new NativeFunction(E("il2cpp_method_get_param_count"), 'uint32', ['pointer']);
const CFN = new NativeFunction(E("il2cpp_class_from_name"), 'pointer', ['pointer', 'pointer', 'pointer']);
const ANEW = new NativeFunction(E("il2cpp_array_new"), 'pointer', ['pointer', 'uint64']);
const INVOKE = new NativeFunction(E("il2cpp_runtime_invoke"), 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
const TATTACH = new NativeFunction(E("il2cpp_thread_attach"), 'pointer', ['pointer']);

const STEPS = [];
function imgName() {
  const sp = Memory.alloc(8);
  const asms = A(D(), sp), n = Number(sp.readU64().toString());
  const out = [];
  for (let i = 0; i < n; i++) { let img; try { img = I(asms.add(i * Process.pointerSize).readPointer()); } catch (e) { continue; } let nm; try { nm = IN(img).readUtf8String(); } catch (e) { continue; } out.push(nm); }
  return out;
}
function imageByName(name) {
  const sp = Memory.alloc(8);
  const asms = A(D(), sp), n = Number(sp.readU64().toString());
  for (let i = 0; i < n; i++) { let img; try { img = I(asms.add(i * Process.pointerSize).readPointer()); } catch (e) { continue; } let nm; try { nm = IN(img).readUtf8String(); } catch (e) { continue; } if (nm === name) return img; }
  return null;
}
function classByName(img, ns, name) { return CFN(img, Memory.allocUtf8String(ns), Memory.allocUtf8String(name)); }
function methodByName(klass, name, nparams) {
  let it = Memory.alloc(Process.pointerSize); it.writePointer(NULL); let m;
  while (!(m = CM(klass, it)).isNull()) { let mn = ''; try { mn = MN(m).readUtf8String(); } catch (e) {} if (mn === name && (nparams == null || MPC(m) === nparams)) return m; }
  return null;
}
function hexToBytes(hex) { const n = hex.length / 2; const a = new Uint8Array(n); for (let i = 0; i < n; i++) a[i] = parseInt(hex.substr(i * 2, 2), 16); return a; }

rpc.exports.listImages = function () { return imgName(); };

rpc.exports.call = function (cls, method, argHexes) {
  try {
    TATTACH(D());
    STEPS.length = 0;
    STEPS.push('attached');
    const img = imageByName('Assembly-CSharp.dll');
    if (!img) return { error: 'no Assembly-CSharp' };
    const klass = classByName(img, '', cls);
    STEPS.push('klass=' + (klass ? klass.toString() : 'null'));
    if (!klass || klass.isNull()) return { error: 'no class', steps: STEPS };
    const m = methodByName(klass, method, argHexes.length);
    STEPS.push('method=' + (m ? m.toString() : 'null'));
    if (!m || m.isNull()) return { error: 'no method', steps: STEPS, images: null };
    const mscorlib = imageByName('mscorlib.dll') || imageByName('System.Private.CoreLib.dll');
    STEPS.push('mscorlib=' + (mscorlib ? mscorlib.toString() : 'null'));
    const byteKlass = classByName(mscorlib, 'System', 'Byte');
    STEPS.push('byteKlass=' + (byteKlass ? byteKlass.toString() : 'null'));
    if (!byteKlass || byteKlass.isNull()) return { error: 'no Byte class', steps: STEPS, images: imgName() };
    const n = argHexes.length;
    const args = Memory.alloc(8 * Math.max(1, n));
    for (let i = 0; i < n; i++) {
      const bytes = hexToBytes(argHexes[i]);
      const arr = ANEW(byteKlass, bytes.length);
      STEPS.push('arg' + i + ' arr=' + (arr ? arr.toString() : 'null') + ' len=' + bytes.length);
      if (!arr || arr.isNull()) return { error: 'array_new null', steps: STEPS };
      arr.add(0x20).writeByteArray(bytes.buffer);
      args.add(i * 8).writePointer(arr);
    }
    const exc = Memory.alloc(8); exc.writePointer(NULL);
    STEPS.push('pre-invoke args=' + args.toString());
    let res;
    try { res = INVOKE(m, NULL, args, exc); }
    catch (ie) { return { error: 'invoke threw: ' + ie, steps: STEPS }; }
    STEPS.push('invoked res=' + (res ? res.toString() : 'null'));
    STEPS.push('exc=' + exc.readPointer().toString());
    let out = null;
    if (res && !res.isNull()) {
      const len = Number(res.add(0x18).readS64().toString());
      const b = new Uint8Array(res.add(0x20).readByteArray(Math.min(len, 64)));
      out = { len: len, head: Array.from(b).map(x => (x >= 32 && x < 127) ? String.fromCharCode(x) : '.').join(''), hex: Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('') };
    }
    return { ok: true, result: out, steps: STEPS, exc: exc.readPointer().toString() };
  } catch (e) { return { error: '' + e, steps: STEPS }; }
};
