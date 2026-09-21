// Read the static string values of a class (default: zf) — read-only.
rpc.exports.zfread = function (cls) {
  const name = cls || "zf";
  return Il2Cpp.perform(() => {
    const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    const k = img.class(name);
    const out = {};
    for (const f of k.fields) {
      if (!f.isStatic) continue;
      try {
        const v = f.value;
        out[f.name] = (v === null || v === undefined) ? null : String(v);
      } catch (e) {
        out[f.name] = "ERR: " + e;
      }
    }
    return JSON.stringify(out);
  });
};
