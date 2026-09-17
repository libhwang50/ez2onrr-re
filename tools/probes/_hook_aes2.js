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

// Verify that [p, p+span) lies fully inside ONE readable range before touching it.
function spanReadable(p, span) {
  if (!p || p.isNull()) return false;
  try {
    const r = Process.findRangeByAddress(p);
    if (!r || r.protection.indexOf('r') < 0) return false;
    const start = r.base, end = r.base.add(r.size);
    return p.compare(start) >= 0 && p.add(span).compare(end) <= 0;
  } catch (e) { return false; }
}

function readArraySafe(p, maxlen) {
  if (!spanReadable(p, 0x20 + maxlen)) return null;
  try {
    const len = Number(p.add(0x18).readS64().toString());
    if (len <= 0 || len > maxlen) return null;
    if (!spanReadable(p, 0x20 + len)) return null;
    const b = new Uint8Array(p.add(0x20).readByteArray(len));
    let s = ''; for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
    return { len: len, hex: s };
  } catch (e) { return null; }
}

const EVENTS = [];

function hookCtor(imageName, clsName) {
  const k = findClass(imageName, clsName);
  if (!k) return { cls: clsName, attached: 0, err: 'not found' };
  let it = Memory.alloc(Process.pointerSize); it.writePointer(NULL);
  let m, attached = 0;
  while (!(m = CM(k, it)).isNull()) {
    let mn = ''; try { mn = MN(m).readUtf8String(); } catch (e) {}
    if (mn !== '.ctor') continue;
    const ptr = m.readPointer();
    Interceptor.attach(ptr, {
      onEnter: function (args) {
        const arrs = [];
        for (let i = 0; i < 6; i++) {
          const a = readArraySafe(args[i], 256);
          if (a) arrs.push({ i: i, len: a.len, hex: a.hex });
        }
        if (arrs.length) EVENTS.push({ cls: clsName, arrs: arrs });
      }
    });
    attached++;
  }
  return { cls: clsName, attached: attached };
}

rpc.exports.start = function () {
  const r1 = hookCtor('System.Core.dll', 'AesTransform');
  const r2 = hookCtor('mscorlib.dll', 'RijndaelManagedTransform');
  return [r1, r2];
};
rpc.exports.drain = function () { const e = EVENTS.slice(); EVENTS.length = 0; return e; };
