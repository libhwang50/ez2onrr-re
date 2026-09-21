// Scan the module for code that touches zf's static fields (aes_key @ +0x10,
// aes_iv @ +0x18): find `mov r64,[r64+0xb8]` (static_fields load) followed by
// a write to [r64+0x10] or [r64+0x18] or an `add r64,0x10/0x18`, then verify
// the klass pointer (loaded RIP-relative just before) is named "zf".
// Read-only.
rpc.exports.zfscan = function () {
  const mod = Process.getModuleByName("GameAssembly.dll");
  const base = mod.base, size = mod.size;
  const CH = 0x100000;
  const nameRead = (p) => {
    try { return ptr(p).readCString(); } catch (e) { return null; }
  };
  const klassName = (slot) => {
    try {
      const k = ptr(slot).readPointer();      // slot holds Il2CppClass*
      return nameRead(k.add(0x10).readPointer());
    } catch (e) { return null; }
  };
  const hits = [];
  let cover = 0, pat8b = 0, badchunk = 0, out_err = null;
  for (let off = 0; off < size; off += CH) {
    let buf;
    const n = Math.min(CH, size - off);
    try { buf = new Uint8Array(base.add(off).readByteArray(n)); cover += buf.length; }
    catch (e) { if (!out_err) out_err = '' + e + ' @' + (base + off); badchunk++; continue; }
    for (let i = 0; i + 16 <= buf.length; i++) {
      if (buf[i] !== 0x48 || buf[i + 1] !== 0x8b) continue;
      const m = buf[i + 2];
      if ((m & 0xc0) !== 0x80 || (m & 0x38) === 0x20) continue; // need reg-mem, mem=reg
      if (buf[i + 3] !== 0xb8 || buf[i + 4] || buf[i + 5] || buf[i + 6]) continue;
      pat8b++;
      // find the NEAREST klass load (48 8B 0D/05/15 disp32) before this site
      let kaddr = null;
      for (let j = i - 7; j >= i - 40 && j >= 0; j -= 1) {
        if (buf[j] === 0x48 && buf[j + 1] === 0x8b &&
            (buf[j + 2] === 0x0d || buf[j + 2] === 0x05 || buf[j + 2] === 0x15)) {
          const disp = buf[j + 3] | (buf[j + 4] << 8) | (buf[j + 5] << 16) | (buf[j + 6] << 24);
          const d2 = disp | 0; // signed
          kaddr = base.add(off + j).add(7 + d2);
          break;
        }
      }
      if (kaddr === null) continue;
      let kn = null;
      try { kn = klassName(kaddr); } catch (e) { kn = null; }
      if (kn !== "zf") continue;
      // look for a write to [reg+0x10/0x18] or add reg,0x10/0x18 within 24 bytes
      for (let j2 = i + 7; j2 < Math.min(i + 31, buf.length - 4); j2++) {
        const b0 = buf[j2], b1 = buf[j2 + 1], b2 = buf[j2 + 2], b3 = buf[j2 + 3];
        let kind = null, disp = 0;
        if (b0 === 0x48 && b1 === 0x89 && (b2 & 0xc0) === 0x40) { // mov [reg+disp8], reg
          disp = b3; kind = "mov [r+disp],r";
        } else if (b0 === 0x48 && b1 === 0x83 && (b2 & 0xc0) === 0xc0 && (b3 === 0x10 || b3 === 0x18)) {
          disp = b3; kind = "add r,disp";
        }
        if (kind && (disp === 0x10 || disp === 0x18)) {
          hits.push({
            va: base.add(off + i).toString(16),
            site: base.add(off + j2).toString(16),
            kind: kind, disp: disp.toString(16),
          });
          break;
        }
      }
    }
  }
  return JSON.stringify({ base: base.toString(16), size: size, cover: cover, pat8b: pat8b, badchunk: badchunk, err: out_err, hits: hits });
};
