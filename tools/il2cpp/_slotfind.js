// _slotfind.js — dump the IL2CPP class struct and locate vtable entries.
// Read-only: no hooks, no writes.
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }

const HI = (p) => Math.floor(Number(p.toString()) / 4294967296);
const LO = (p) => (Number(p.toString()) >>> 0);

function scanClass(kp, win, base, size, targets) {
  const mbase = Number(base.toString());
  const mend = mbase + size;
  const u = new Uint8Array(kp.readByteArray(win));
  const dv = new DataView(u.buffer);
  const res = { modulePtrs: [], targets: {}, cls: kp.toString() };
  for (const t of targets) res.targets[t.toLowerCase()] = [];
  for (let off = 0; off + 8 <= win; off += 8) {
    const lo = dv.getUint32(off, true), hi = dv.getUint32(off + 4, true);
    const v = hi * 4294967296 + lo;
    if (v < mbase || v >= mend) continue;
    const hex = '0x' + hi.toString(16).padStart(8, '0') + (lo >>> 0).toString(16).padStart(8, '0');
    if (res.modulePtrs.length < 600) res.modulePtrs.push({ off: '0x' + off.toString(16), va: hex });
    if (res.targets[hex.toLowerCase()]) res.targets[hex.toLowerCase()].push('0x' + off.toString(16));
  }
  return res;
}

rpc.exports.cls = function (asmName, clsName, targets) {
  return onMain(() => {
    let k = null;
    try {
      const img = Il2Cpp.domain.assembly(asmName).image;
      for (const c of img.classes) if (c.name === clsName) { k = c; break; }
    } catch (e) { return { err: '' + e }; }
    if (!k) return { err: 'no class' };
    const m = Process.getModuleByName('GameAssembly.dll');
    const out = scanClass(k.handle, 0x4000, m.base, m.size, targets || []);
    out.name = clsName;
    out.base = m.base.toString();
    out.size = m.size;
    out.klass = k.handle.toString();
    return out;
  });
};

// Find the concrete class pointer of a live object by calling a 0-arg ctor.
rpc.exports.inst = function (asmName, clsName, targets) {
  return onMain(() => {
    let k = null;
    try {
      const img = Il2Cpp.domain.assembly(asmName).image;
      for (const c of img.classes) if (c.name === clsName) { k = c; break; }
    } catch (e) { return { err: '' + e }; }
    if (!k) return { err: 'no class' };
    const m = Process.getModuleByName('GameAssembly.dll');
    let obj;
    try { obj = k.new(); } catch (e) { return { err: 'new: ' + e }; }
    const kp = obj.handle.readPointer();
    const out = scanClass(kp, 0x4000, m.base, m.size, targets || []);
    out.name = clsName;
    out.obj = obj.handle.toString();
    out.klassOfObj = kp.toString();
    return out;
  });
};
