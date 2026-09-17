rpc.exports.scan = function(pat) {
  const results = [];
  let ranges;
  try { ranges = Process.enumerateRanges('r--'); } catch(e) { ranges = Process.enumerateRanges({protection:'r--'}); }
  for (const r of ranges) {
    if (r.size < 0x1000) continue;
    let m;
    try { m = Memory.scanSync(r.base, r.size, pat); } catch(e) { continue; }
    for (const x of m) {
      results.push({ address: x.address.toString(), range: r.base.toString() + '+' + r.size.toString(16), prot: r.protection });
      if (results.length >= 60) return results;
    }
  }
  return results;
};
rpc.exports.dump = function(addr, len) {
  const p = ptr(addr);
  const b = new Uint8Array(p.readByteArray(len));
  let hex = ''; for (let i=0;i<b.length;i++) hex += b[i].toString(16).padStart(2,'0');
  return hex;
};
