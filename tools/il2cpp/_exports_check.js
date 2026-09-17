rpc.exports.run = function (name, exps) {
  const m = Process.getModuleByName(name);
  const out = {};
  for (const e of exps) {
    try {
      const a = m.getExportByName(e);
      const b = new Uint8Array(a.readByteArray(16));
      let s = ''; for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
      out[e] = { addr: a.toString(), hex: s };
    } catch (err) { out[e] = { err: '' + err }; }
  }
  return out;
};
