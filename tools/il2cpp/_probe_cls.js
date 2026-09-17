// _probe_cls.js — verify the Il2CppClass pointer layout. Read-only.
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }

rpc.exports.probe = function (asmName, clsName) {
  return onMain(() => {
    const out = {};
    let k = null;
    try {
      const img = Il2Cpp.domain.assembly(asmName).image;
      for (const c of img.classes) if (c.name === clsName) { k = c; break; }
    } catch (e) { return { err: '' + e }; }
    if (!k) return { err: 'no class' };
    const kp = k.handle;
    out.cls = kp.toString();
    out.rt = kp.readPointer().toString();
    // walk first 0x80 bytes, print qwords and any ASCII strings
    const u = new Uint8Array(kp.readByteArray(0x400));
    const dv = new DataView(u.buffer);
    const rows = [];
    for (let off = 0; off < 0x80; off += 8) {
      const lo = dv.getUint32(off, true), hi = dv.getUint32(off + 4, true);
      rows.push('+' + off.toString(16) + ' = 0x' + hi.toString(16) + (lo >>> 0).toString(16).padStart(8, '0'));
    }
    out.head = rows;
    // try reading name at 0x10 and namespaze at 0x18
    const tryStr = (off) => { try { return kp.add(off).readPointer().readUtf8String(); } catch (e) { return 'ERR:' + e; } };
    out.name_0x10 = tryStr(0x10);
    out.ns_0x18 = tryStr(0x18);
    out.nameField = (() => { try { return k.name; } catch (e) { return 'ERR'; } })();
    return out;
  });
};
