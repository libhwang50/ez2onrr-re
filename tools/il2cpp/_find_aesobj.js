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

rpc.exports.fields = function () {
  const out = {};
  for (const [img, cls] of [['System.Core.dll', 'AesTransform'], ['System.Core.dll', 'SymmetricTransform']]) {
    const k = findClass(img, cls);
    if (!k) { out[cls] = null; continue; }
    const fs = [];
    let it = Memory.alloc(Process.pointerSize); it.writePointer(NULL);
    let f;
    while (!(f = FL(k, it)).isNull()) {
      let tn = null; try { tn = TN(FT(f)).readUtf8String(); } catch (e) {}
      fs.push({ name: FN(f).readUtf8String(), off: FO(f), type: tn });
    }
    out[cls] = { klass: k.toString(), fields: fs };
  }
  return out;
};

function readU32Array(p) {
  if (!p || p.isNull()) return null;
  try {
    const r = Process.findRangeByAddress(p);
    if (!r || r.protection.indexOf('r') < 0) return null;
    const len = Number(p.add(0x18).readS64().toString());
    if (len < 4 || len > 200) return null;
    const arr = p.add(0x20).readByteArray(len * 4);
    return { len: len, words: new Uint32Array(arr) };
  } catch (e) { return null; }
}

rpc.exports.scanAes = function (offsets, maxHits) {
  const k = findClass('System.Core.dll', 'AesTransform');
  if (!k) return { error: 'no AesTransform' };
  const pat = Array.from(new Uint8Array(k.readByteArray(8))).map(b => b.toString(16).padStart(2, '0')).join(' ');
  const results = [];
  const seen = {};
  const ranges = Process.enumerateRanges('rw-');
  for (const r of ranges) {
    if (r.size < 64 || r.size > 256 * 1024 * 1024) continue;
    let m; try { m = Memory.scanSync(r.base, r.size, pat); } catch (e) { continue; }
    for (const x of m) {
      if (results.length >= maxHits) break;
      const a = x.address;
      const ek = readU32Array(a.add(offsets.expandedKey).readPointer());
      if (!ek) continue;
      if (!(ek.len === 44 || ek.len === 52 || ek.len === 60)) continue;
      const nk = ek.len === 44 ? 4 : ek.len === 52 ? 6 : 8;
      // original key = first Nk words big-endian
      let key = '';
      for (let i = 0; i < nk; i++) {
        const w = ek.words[i];
        key += ((w >>> 24) & 0xff).toString(16).padStart(2, '0') + ((w >>> 16) & 0xff).toString(16).padStart(2, '0') +
               ((w >>> 8) & 0xff).toString(16).padStart(2, '0') + (w & 0xff).toString(16).padStart(2, '0');
      }
      // IV: try to read via algo field if present
      let iv = null;
      try {
        if (offsets.algo) {
          const algo = a.add(offsets.algo).readPointer();
          for (const [ialgo, civ] of [[offsets.ivOff, null]]) {}
          if (offsets.ivOff) iv = readU32Array(algo.add(offsets.ivOff).readPointer());
        }
      } catch (e) {}
      if (!seen[key]) { seen[key] = 1; results.push({ addr: a.toString(), nk: nk, key: key, ivWords: iv ? iv.len : null }); }
    }
    if (results.length >= maxHits) break;
  }
  return { klass: k.toString(), results: results };
};
