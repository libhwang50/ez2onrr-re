const mod = Process.getModuleByName("GameAssembly.dll");
const E = n => mod.getExportByName(n);
const D = new NativeFunction(E("il2cpp_domain_get"), 'pointer', []);
const A = new NativeFunction(E("il2cpp_domain_get_assemblies"), 'pointer', ['pointer', 'pointer']);
const I = new NativeFunction(E("il2cpp_assembly_get_image"), 'pointer', ['pointer']);
const IN = new NativeFunction(E("il2cpp_image_get_name"), 'pointer', ['pointer']);
const CC = new NativeFunction(E("il2cpp_image_get_class_count"), 'uint32', ['pointer']);
const CL = new NativeFunction(E("il2cpp_image_get_class"), 'pointer', ['pointer', 'uint32']);
const CN = new NativeFunction(E("il2cpp_class_get_name"), 'pointer', ['pointer']);
const CM = new NativeFunction(E("il2cpp_class_get_methods"), 'pointer', ['pointer', 'pointer']);
const MN = new NativeFunction(E("il2cpp_method_get_name"), 'pointer', ['pointer']);

function hexOf(p, maxlen) {
  if (!p || p.isNull()) return null;
  try {
    const len = Number(p.add(0x18).readS64().toString());
    if (len <= 0 || len > maxlen) return null;
    const b = new Uint8Array(p.add(0x20).readByteArray(len));
    let s = ''; for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
    return { len: len, hex: s };
  } catch (e) { return null; }
}

function findClass(imageName, clsName) {
  const dom = D(), sp = Memory.alloc(8);
  const asms = A(dom, sp), n = Number(sp.readU64().toString());
  for (let i = 0; i < n; i++) {
    let img; try { img = I(asms.add(i * Process.pointerSize).readPointer()); } catch (e) { continue; }
    let nm; try { nm = IN(img).readUtf8String(); } catch (e) { continue; }
    if (nm !== imageName) continue;
    const cnt = CC(img);
    for (let c = 0; c < cnt; c++) {
      const k = CL(img, c);
      if (k.isNull()) continue;
      if (CN(k).readUtf8String() === clsName) return k;
    }
  }
  return null;
}

function hookCtor(klass, label) {
  if (!klass) { send('[hook] class not found: ' + label); return; }
  let it = Memory.alloc(Process.pointerSize); it.writePointer(NULL);
  let m;
  let count = 0;
  while (!(m = CM(klass, it)).isNull()) {
    let mn = ''; try { mn = MN(m).readUtf8String(); } catch (e) {}
    if (mn === '.ctor') {
      const ptr = m.readPointer();
      try {
        Interceptor.attach(ptr, {
          onEnter: function (args) {
            // Mono AesTransform/SymmetricTransform ctor args vary; scan first 6 args
            // for two byte[]-looking pointers and log them.
            const info = [];
            for (let i = 0; i < 6; i++) {
              const a = args[i];
              let r = null;
              try {
                const len = Number(a.add(0x18).readS64().toString());
                if (len > 0 && len <= 512) {
                  const b = new Uint8Array(a.add(0x20).readByteArray(Math.min(len, 64)));
                  let s = ''; for (let j = 0; j < b.length; j++) s += b[j].toString(16).padStart(2, '0');
                  r = { len: len, hex: s };
                }
              } catch (e) {}
              info.push(r);
            }
            send({ type: 'aes-ctor', label: label, args: info });
          }
        });
        send('[hook] attached ' + label + ' .ctor @ ' + ptr);
        count++;
      } catch (e) { send('[hook] attach fail ' + label + ': ' + e); }
    }
  }
  return count;
}

rpc.exports.start = function () {
  const c1 = findClass('System.Core.dll', 'AesTransform');
  const c2 = findClass('mscorlib.dll', 'RijndaelManagedTransform');
  const n1 = hookCtor(c1, 'System.Core.AesTransform');
  const n2 = hookCtor(c2, 'mscorlib.RijndaelManagedTransform');
  send('[hook] done: AesTransform ctors=' + n1 + ' Rijndael ctors=' + n2);
  return { a: n1, r: n2 };
};
