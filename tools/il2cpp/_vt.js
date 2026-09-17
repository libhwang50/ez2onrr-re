// _vt.js — locate AES-related methods and the RijndaelManagedTransform vtable layout.
// Read-only: no hooks, no writes.
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }

rpc.exports.vt = function () {
  return onMain(() => {
    const out = { mod: {}, classes: {} };
    try {
      const m = Process.getModuleByName('GameAssembly.dll');
      out.mod.base = m.base.toString();
      out.mod.size = m.size;
    } catch (e) { out.mod.err = '' + e; }

    const grab = (asmName, clsName) => {
      const key = asmName + ':' + clsName;
      out.classes[key] = { methods: {}, fields: {} };
      try {
        const img = Il2Cpp.domain.assembly(asmName).image;
        let k = null;
        for (const c of img.classes) if (c.name === clsName) { k = c; break; }
        if (!k) { out.classes[key].err = 'class not found'; return; }
        out.classes[key].klass = k.handle.toString();
        out.classes[key].vtable = (() => { try { return k.vtable ? k.vtable.toString() : null; } catch (e) { return null; } })();
        for (const m of k.methods) {
          let va; try { va = m.virtualAddress; } catch (e) { continue; }
          if (va.isNull()) continue;
          out.classes[key].methods[m.name + '/' + m.parameterCount] = va.toString();
        }
        for (const f of k.fields) {
          let off = null; try { off = f.offset; } catch (e) { off = 'ERR'; }
          out.classes[key].fields[f.name] = { off: off, type: (() => { try { return f.type.name; } catch (e) { return '?'; } })() };
        }
      } catch (e) { out.classes[key].err = '' + e; }
    };

    grab('mscorlib', 'RijndaelManagedTransform');
    grab('mscorlib', 'RijndaelManaged');
    grab('mscorlib', 'SymmetricAlgorithm');
    grab('Assembly-CSharp', 'da');
    grab('Assembly-CSharp', 'zf');
    grab('Assembly-CSharp', 'InGameCore');
    grab('System.Core', 'AesManaged');
    return out;
  });
};

// Raw read: returns hex of N bytes at addr, plus the enclosing module RVA.
rpc.exports.raw = function (addr, len) {
  const p = ptr(addr);
  const u = new Uint8Array(p.readByteArray(len));
  let h = ''; for (let i = 0; i < u.length; i++) h += u[i].toString(16).padStart(2, '0');
  let rva = null;
  try {
    const m = Process.getModuleByName('GameAssembly.dll');
    rva = '0x' + p.sub(m.base).toString(16);
  } catch (e) {}
  return { hex: h, rva: rva };
};
