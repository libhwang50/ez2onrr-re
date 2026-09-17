rpc.exports.run = function (name, exp, len) {
    const m = Process.getModuleByName(name);
    const a = m.getExportByName(exp);
    const b = new Uint8Array(a.readByteArray(len));
    let s = ''; for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
    return { addr: a.toString(), rva: a.sub(m.base).toString(), hex: s };
};
rpc.exports.readAt = function (name, rva, len) {
    const m = Process.getModuleByName(name);
    const b = new Uint8Array(m.base.add(rva).readByteArray(len));
    let s = ''; for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
    return s;
};
