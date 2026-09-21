// Invoke zf's string-literal thunks (default aes_key/aes_iv/publicKey) and
// compare with the live static values. Read-only.
rpc.exports.zflit = function () {
  return Il2Cpp.perform(() => {
    const readStr = (p) => {
      if (p.isNull()) return null;
      const len = p.add(0x10).readS32();
      return p.add(0x14).readUtf16String(len);
    };
    const thunks = {
      aes_key_default: "0x6ffff31ea5f0",
      aes_iv_default: "0x6ffff31ea690",
      publicKey_default: "0x6ffff31ea730",
    };
    const out = {};
    for (const [name, va] of Object.entries(thunks)) {
      const f = new NativeFunction(ptr(va), 'pointer', []);
      try { out[name] = readStr(f()); } catch (e) { out[name] = "ERR: " + e; }
    }
    // live statics
    const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    const zf = img.class("zf");
    for (const f of zf.fields) {
      if (!f.isStatic) continue;
      if (["aes_key", "aes_iv", "publicKey"].includes(f.name)) {
        try { out["live_" + f.name] = String(f.value); } catch (e) { out["live_" + f.name] = "ERR"; }
      }
    }
    return JSON.stringify(out);
  });
};
