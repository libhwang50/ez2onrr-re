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
const FL = new NativeFunction(E("il2cpp_class_get_fields"), 'pointer', ['pointer', 'pointer']);
const FN = new NativeFunction(E("il2cpp_field_get_name"), 'pointer', ['pointer']);
const FO = new NativeFunction(E("il2cpp_field_get_offset"), 'uint32', ['pointer']);
const FT = new NativeFunction(E("il2cpp_field_get_type"), 'pointer', ['pointer']);
const TN = new NativeFunction(E("il2cpp_type_get_name"), 'pointer', ['pointer']);
const FSF = new NativeFunction(E("il2cpp_field_get_flags"), 'uint32', ['pointer']);
const FSV = new NativeFunction(E("il2cpp_field_static_get_value"), 'void', ['pointer', 'pointer']);
const SC = new NativeFunction(E("il2cpp_string_chars"), 'pointer', ['pointer']);
const SL = new NativeFunction(E("il2cpp_string_length"), 'int32', ['pointer']);

function RS(p) {
  if (!p || p.isNull()) return null;
  try { const l = SL(p); if (l <= 0 || l > 20000) return null; return SC(p).readUtf16String(l); } catch (e) { return null; }
}

function findClass(target) {
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
      if (CN(k).readUtf8String() === target) return k;
    }
  }
  return null;
}

function dumpClass(k) {
  const fs = [];
  let it = Memory.alloc(Process.pointerSize); it.writePointer(NULL);
  let fld;
  while (!(fld = FL(k, it)).isNull()) {
    const fn = FN(fld).readUtf8String();
    let t = null; try { t = TN(FT(fld)).readUtf8String(); } catch (e) {}
    let flags = 0; try { flags = FSF(fld); } catch (e) {}
    fs.push({ name: fn, type: t, off: FO(fld), static: (flags & 0x10) !== 0, field: fld });
  }
  return fs;
}

rpc.exports.run = function () {
  const out = {};
  for (const cls of ["vy", "vx", "zf", "qe"]) {
    const k = findClass(cls);
    if (!k) { out[cls] = { error: "not found" }; continue; }
    out[cls] = { fields: dumpClass(k) };
  }
  // resolve vy.instance -> member (vx) -> AES_KEY / AES_IV
  const vyK = findClass("vy");
  const vyFs = dumpClass(vyK);
  const instF = vyFs.find(f => f.name === "instance");
  const memberF = vyFs.find(f => f.name === "member");
  out.vyResult = {};
  if (instF && instF.static) {
    const vp = Memory.alloc(Process.pointerSize);
    FSV(instF.field, vp);
    const inst = vp.readPointer();
    out.vyResult.instance = inst.toString();
    if (memberF && !memberF.static && !inst.isNull()) {
      const mem = inst.add(memberF.off).readPointer();
      out.vyResult.member = mem.toString();
      // read vx fields (AES_KEY@0x40, AES_IV@0x48, MEMBER_ID@0x10, DLC@0x18, STEAM_ID@0x20)
      const vxK = findClass("vx");
      const vxFs = dumpClass(vxK);
      const mo = {};
      for (const f of vxFs) {
        if (f.off <= 0) continue;
        if ((f.type || "").indexOf("System.String") >= 0) mo[f.name] = RS(mem.add(f.off).readPointer());
        else if (f.type === "System.Int32") mo[f.name] = mem.add(f.off).readS32();
      }
      out.vyResult.memberFields = mo;
    }
  }
  return out;
};
