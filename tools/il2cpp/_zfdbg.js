// Debug: hand-check the zf static-write pattern at the .cctor site.
rpc.exports.zfdbg = function () {
  const out = {};
  const site = ptr("0x6ffff2d73b96"); // mov rcx,[rip+disp] in zf..cctor
  const bytes = site.readByteArray(0x30);
  out.bytes = Array.from(new Uint8Array(bytes)).map(b => b.toString(16)).join(' ');
  // decode rip-relative
  const b = new Uint8Array(bytes);
  if (b[0] === 0x48 && b[1] === 0x8b && b[2] === 0x0d) {
    const disp = b[3] | (b[4] << 8) | (b[5] << 16) | ((b[6] << 24) >>> 0);
    // make signed
    const d2 = disp | 0;
    const slot = site.add(7 + d2);
    out.slot = slot.toString(16);
    try {
      const k = slot.readPointer();
      out.klass = k.toString(16);
      const namep = k.add(0x10).readPointer();
      out.name = namep.readCString();
      const sf = k.add(0xb8).readPointer();
      out.static_fields = sf.toString(16);
      // read the aes_key static string object
      const aesKeyPtr = sf.readPointer(); // +0
      out.static0 = aesKeyPtr.toString(16);
    } catch (e) { out.err = '' + e; }
  }
  return JSON.stringify(out);
};
