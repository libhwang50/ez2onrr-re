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
const FSF = new NativeFunction(E("il2cpp_field_get_flags"), 'uint32', ['pointer']);
const FSV = new NativeFunction(E("il2cpp_field_static_get_value"), 'void', ['pointer', 'pointer']);
const OGC = new NativeFunction(E("il2cpp_object_get_class"), 'pointer', ['pointer']);
const SC = new NativeFunction(E("il2cpp_string_chars"), 'pointer', ['pointer']);
const SL = new NativeFunction(E("il2cpp_string_length"), 'int32', ['pointer']);

function RS(p) {
  if (!p || p.isNull()) return null;
  try { const l = SL(p); if (l < 0 || l > 4000) return null; return SC(p).readUtf16String(l); } catch (e) { return null; }
}

function findIGC() {
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
        offs[fn] = { off: FO(f), field: f };
        if (fn === "instance") instF = f;
      }
      const vp = Memory.alloc(Process.pointerSize);
      FSV(instF, vp);
      return { inst: vp.readPointer(), offs: offs };
    }
  }
  return null;
}

rpc.exports.dict = function (fieldName) {
  const g = findIGC();
  if (!g) return { error: 'no igc' };
  const f = g.offs[fN];
  return { error: 'x' };
};

rpc.exports.run = function (fieldName, maxEntries) {
  const g = findIGC();
  if (!g || !g.offs[fieldName]) return { error: 'no field ' + fieldName };
  const dict = g.inst.add(g.offs[fieldName].off).readPointer();
  if (dict.isNull()) return { error: 'null dict' };
  const dk = OGC(dict);
  // enumerate fields of the dictionary class
  const dofs = {};
  let it = Memory.alloc(Process.pointerSize); it.writePointer(NULL);
  let fld;
  while (!(fld = FL(dk, it)).isNull()) {
    let tn = null; try { tn = TN(FT(fld)).readUtf8String(); } catch (e) {}
    dofs[FN(fld).readUtf8String()] = { off: FO(fld), type: tn };
  }
  const count = dofs['_count'] ? dict.add(dofs['_count'].off).readS32() : null;
  const entries = dofs['_entries'] ? dict.add(dofs['_entries'].off).readPointer() : null;
  const out = { klass: dk.toString(), count: count, dictFields: dofs, entries: [] };
  out.dictHex = Array.from(new Uint8Array(dict.readByteArray(0x60))).map(b => b.toString(16).padStart(2, '0')).join(' ');
  if (!entries || entries.isNull()) return out;
  const elen = Number(entries.add(0x18).readS64().toString());
  const ebase = entries.add(0x20);
  out.entryArrayLen = elen;
  // Entry<int,string>: guess layout {int hash, int next, int key, string value} -> stride 0x18
  // dump raw bytes of first entry to help calibration
  out.firstEntryHex = Array.from(new Uint8Array(ebase.readByteArray(48))).map(b => b.toString(16).padStart(2, '0')).join(' ');
  const n = Math.min(count, maxEntries);
  for (let i = 0; i < n; i++) {
    const e = ebase.add(i * 0x18);
    const hash = e.readS32();
    if (hash === 0 && i > 0) continue; // empty slot
    const key = e.add(8).readS32();
    const val = RS(e.add(0x10).readPointer());
    out.entries.push({ i: i, hash: hash, key: key, val: val });
  }
  return out;
};
