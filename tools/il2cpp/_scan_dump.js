rpc.exports.scan = function (patHex) {
    const R = [];
    const ranges = Process.enumerateRanges('rw-');
    for (const r of ranges) {
        if (r.size < 64 || r.size > 256 * 1024 * 1024) continue;
        let m;
        try { m = Memory.scanSync(r.base, r.size, patHex); } catch (e) { continue; }
        for (const x of m) { R.push(x.address.toString()); if (R.length >= 20) return R; }
    }
    return R;
};
rpc.exports.dump = function (addr, len) {
    try {
        const b = new Uint8Array(ptr(addr).readByteArray(len));
        let s = '';
        for (let i = 0; i < b.length; i++) {
            const c = b[i];
            s += (c >= 32 && c < 127) ? String.fromCharCode(c) : '\\x' + c.toString(16).padStart(2, '0');
        }
        return s;
    } catch (e) { return 'ERR ' + e; }
};
