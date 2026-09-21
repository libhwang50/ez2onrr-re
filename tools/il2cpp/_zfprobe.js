// Probe: largest readByteArray that works through this gadget.
rpc.exports.zfprobe = function () {
  const out = {};
  const p = Process.getModuleByName("GameAssembly.dll").base;
  for (const sz of [0x1000, 0x10000, 0x40000, 0x100000, 0x400000]) {
    try {
      const b = p.readByteArray(sz);
      out['0x' + sz.toString(16)] = b === null ? "NULL" : ("ok " + b.byteLength);
    } catch (e) { out['0x' + sz.toString(16)] = "ERR " + e; }
  }
  return JSON.stringify(out);
};
