// Read zf.aes_key / zf.aes_iv statics (the API session key). Read-only.
rpc.exports.readkey = function () {
  return Il2Cpp.perform(() => {
    const zf = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("zf");
    const read = (name) => {
      try {
        const v = zf.field(name).value;
        if (v === null || v === undefined) return null;
        // bridge may hand us an Il2Cpp.String — prefer .content, else String()
        let s;
        try { s = v.content; } catch (e) { s = undefined; }
        if (typeof s !== 'string') s = String(v);
        return s;
      } catch (e) { return 'ERR: ' + e; }
    };
    return JSON.stringify({ aes_key: read("aes_key"), aes_iv: read("aes_iv") });
  });
};
