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
      while (!(f = FL(k, it)).isNull()) {
        const fn = FN(f).readUtf8String();
        let t = null; try { t = TN(FT(f)).readUtf8String(); } catch (e) {}
        offs[fn] = { off: FO(f), type: t, field: f };
        if (fn === "instance") instF = f;
      }
      const vp = Memory.alloc(Process.pointerSize);
      FSV(instF, vp);
      CACHE = { inst: vp.readPointer(), offs: offs, img: img, klass: k };
      return CACHE;
    }
  }
  return null;
}

function listCount(p) { if (!p || p.isNull()) return -1; try { return p.add(0x18).readS32(); } catch (e) { return -1; } }
function listItems(p) { if (!p || p.isNull()) return null; try { return p.add(0x10).readPointer(); } catch (e) { return null; } }

function classFieldsByName(cn) {
  const g = igc();
  const img = g.img;
  const cnt = CC(img);
  for (let c = 0; c < cnt; c++) {
    const k = CL(img, c);
    if (k.isNull()) continue;
    let name; try { name = CN(k).readUtf8String(); } catch (e) { continue; }
    if (name !== cn) continue;
    const fs = [];
    let it = Memory.alloc(Process.pointerSize); it.writePointer(NULL);
    let f;
    while (!(f = FL(k, it)).isNull()) {
      let t = null; try { t = TN(FT(f)).readUtf8String(); } catch (e) {}
      fs.push({ name: FN(f).readUtf8String(), off: FO(f), type: t });
    }
    return fs;
  }
  return null;
}

rpc.exports.elementClasses = function (names) {
  const out = {};
  for (const n of names) out[n] = classFieldsByName(n);
  return out;
};

rpc.exports.listInfo = function (fieldName) {
  const g = igc();
  const f = g.offs[fieldName];
  if (!f) return { error: 'no field' };
  const list = g.inst.add(f.off).readPointer();
  const cnt = listCount(list);
  const items = listItems(list);
  const out = { type: f.type, count: cnt };
  if (items && !items.isNull() && cnt > 0) {
    // first element
    const e0 = items.add(0x20).readPointer();
    if (e0 && !e0.isNull()) {
      const c2 = listCount(e0);
      out.firstInnerCount = c2;
      const inner = listItems(e0);
      if (inner && !inner.isNull() && c2 > 0) {
        const obj = inner.add(0x20).readPointer();
        out.firstObj = obj.toString();
        const fs = classFieldsByName('em') || [];
        const vals = {};
        for (const ff of fs) {
          if (ff.off <= 0) continue;
          try {
            if ((ff.type || '').indexOf('System.String') >= 0) vals[ff.name] = RS(obj.add(ff.off).readPointer());
            else if (ff.type === 'System.Int32') vals[ff.name] = obj.add(ff.off).readS32();
            else if (ff.type === 'System.Single') vals[ff.name] = obj.add(ff.off).readFloat();
            else if (ff.type === 'System.Double') vals[ff.name] = obj.add(ff.off).readDouble();
            else if (ff.type === 'System.Boolean') vals[ff.name] = obj.add(ff.off).readU8() !== 0;
          } catch (e) {}
        }
        out.firstElemFields = vals;
      }
    }
  }
  return out;
};
