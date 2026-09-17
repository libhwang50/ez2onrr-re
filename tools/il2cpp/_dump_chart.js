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
const FSV = new NativeFunction(E("il2cpp_field_static_get_value"), 'void', ['pointer', 'pointer']);
const SC = new NativeFunction(E("il2cpp_string_chars"), 'pointer', ['pointer']);
const SL = new NativeFunction(E("il2cpp_string_length"), 'int32', ['pointer']);

function RS(p) { if (!p || p.isNull()) return null; try { const l = SL(p); if (l < 0 || l > 4000) return null; return SC(p).readUtf16String(l); } catch (e) { return null; } }
let CACHE = null;
function igc() {
  if (CACHE) return CACHE;
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
      if (CN(k).readUtf8String() !== "InGameCore") continue;
      let it = Memory.alloc(Process.pointerSize); it.writePointer(NULL);
      let f, instF = null; const offs = {};
      while (!(f = FL(k, it)).isNull()) { const fn = FN(f).readUtf8String(); offs[fn] = { off: FO(f), field: f, type: (() => { try { return TN(FT(f)).readUtf8String(); } catch (e) { return null; } })() }; if (fn === "instance") instF = f; }
      const vp = Memory.alloc(Process.pointerSize); FSV(instF, vp);
      CACHE = { inst: vp.readPointer(), offs: offs, img: img };
      return CACHE;
    }
  }
  return null;
}
function classFields(cn) {
  const img = igc().img; const cnt = CC(img);
  for (let c = 0; c < cnt; c++) { const k = CL(img, c); if (k.isNull()) continue; if (CN(k).readUtf8String() !== cn) continue;
    const fs = []; let it = Memory.alloc(Process.pointerSize); it.writePointer(NULL); let f;
    while (!(f = FL(k, it)).isNull()) { fs.push({ name: FN(f).readUtf8String(), off: FO(f), type: (() => { try { return TN(FT(f)).readUtf8String(); } catch (e) { return null; } })() }); }
    return fs; }
  return [];
}
function readObj(obj, fs) {
  const o = {};
  for (const f of fs) { if (f.off <= 0) continue;
    try { const t = f.type || '';
      if (t.indexOf('System.String') >= 0 && t.indexOf('[]') < 0) o[f.name] = RS(obj.add(f.off).readPointer());
      else if (t === 'System.Int32') o[f.name] = obj.add(f.off).readS32();
      else if (t === 'System.Single') o[f.name] = obj.add(f.off).readFloat();
      else if (t === 'System.Double') o[f.name] = obj.add(f.off).readDouble();
      else if (t === 'System.Boolean') o[f.name] = obj.add(f.off).readU8() !== 0;
      else if (t === 'System.Int64') o[f.name] = Number(obj.add(f.off).readS64().toString());
    } catch (e) {}
  }
  return o;
}
function listCount(p) { try { return p.add(0x18).readS32(); } catch (e) { return -1; } }
function listItems(p) { try { return p.add(0x10).readPointer(); } catch (e) { return null; } }

rpc.exports.dumpField = function (fieldName, elemClass, nested) {
  const g = igc(); const f = g.offs[fieldName];
  if (!f) return { error: 'no field' };
  const fs = classFields(elemClass);
  const root = g.inst.add(f.off).readPointer();
  const n = listCount(root);
  const items = listItems(root);
  const out = [];
  for (let i = 0; i < n; i++) {
    const elem = items.add(0x20 + i * Process.pointerSize).readPointer();
    if (elem.isNull()) continue;
    if (nested) {
      const m = listCount(elem); const inner = listItems(elem); const lane = [];
      for (let j = 0; j < m; j++) { const o = inner.add(0x20 + j * Process.pointerSize).readPointer(); if (!o.isNull()) lane.push(readObj(o, fs)); }
      out.push(lane);
    } else {
      out.push(readObj(elem, fs));
    }
  }
  return { field: fieldName, elemClass: elemClass, elemFields: fs, data: out };
};
