
function readManagedString(p) {
    try {
        if (p.isNull()) return null;
        const len = p.add(0x10).readS32();
        if (len < 0 || len > 4096) return 'BADLEN:' + len;
        const bytes = new Uint8Array(p.add(0x14).readByteArray(len * 2));
        let s = '';
        for (let i = 0; i < len; i++) s += String.fromCharCode(bytes[i * 2] | (bytes[i * 2 + 1] << 8));
        return s;
    } catch (e) { return 'ERR:' + e; }
}
rpc.exports.read = function (addr, keyOff, ivOff) {
    const o = ptr(addr);
    const kp = o.add(keyOff).readPointer();
    const ip = o.add(ivOff).readPointer();
    return { addr: addr, cls: readManagedString ? null : null, key: readManagedString(kp), iv: readManagedString(ip) };
};
rpc.exports.readAll = function (addrs, keyOff, ivOff) {
    const out = [];
    for (const a of addrs) {
        try {
            const o = ptr(a);
            out.push({ addr: a, key: readManagedString(o.add(keyOff).readPointer()), iv: readManagedString(o.add(ivOff).readPointer()) });
        } catch (e) { out.push({ addr: a, err: '' + e }); }
    }
    return out;
};
