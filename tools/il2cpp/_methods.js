// _methods.js — list methods (with VAs) and fields (with offsets) for classes.
// Read-only.
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }

rpc.exports.methods = function (pairs) {
  return onMain(() => {
    const out = {};
    for (const [asmName, clsName] of pairs) {
      const key = asmName + ':' + clsName;
      out[key] = { methods: {}, fields: {}, klass: null };
      try {
        const img = Il2Cpp.domain.assembly(asmName).image;
        let k = null;
        for (const c of img.classes) if (c.name === clsName) { k = c; break; }
        if (!k) { out[key].err = 'not found'; continue; }
        out[key].klass = k.handle.toString();
        for (const m of k.methods) {
          let va; try { va = m.virtualAddress; } catch (e) { continue; }
          if (va.isNull()) continue;
          out[key].methods[m.name + '/' + m.parameterCount] = va.toString();
        }
        for (const f of k.fields) {
          let off = null; try { off = f.offset; } catch (e) { off = 'ERR'; }
          out[key].fields[f.name] = off;
        }
      } catch (e) { out[key].err = '' + e; }
    }
    return out;
  });
};
