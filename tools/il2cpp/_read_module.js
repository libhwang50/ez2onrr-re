rpc.exports.read = function (name, off, len) {
    const m = Process.getModuleByName(name);
    const p = m.base.add(off);
    const b = new Uint8Array(p.readByteArray(len));
    let s = ''; for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
    return { base: m.base.toString(), size: m.size, hex: s };
};
