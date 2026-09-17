
rpc.exports.scan = function (hexpat) {
    const pat = [];
    for (let i = 0; i < hexpat.length; i += 2) pat.push(parseInt(hexpat.substr(i, 2), 16));
    const needle = pat.map(b => b.toString(16).padStart(2, '0')).join(' ');
    const ranges = Process.enumerateRanges({ protection: 'r--', coalesce: true });
    const hits = [];
    for (const r of ranges) {
        if (r.size > 0x4000000) continue;      // skip huge
        if (r.size < 8) continue;
        try {
            const res = Memory.scanSync(r.base, r.size, needle);
            for (const m of res) hits.push(m.address.toString());
        } catch (e) {}
    }
    return hits;
};
rpc.exports.rwscan = function (hexpat) {
    const pat = [];
    for (let i = 0; i < hexpat.length; i += 2) pat.push(parseInt(hexpat.substr(i, 2), 16));
    const needle = pat.map(b => b.toString(16).padStart(2, '0')).join(' ');
    const ranges = Process.enumerateRanges({ protection: 'rw-', coalesce: true });
    const hits = [];
    for (const r of ranges) {
        if (r.size < 8) continue;
        try {
            const res = Memory.scanSync(r.base, r.size, needle);
            for (const m of res) hits.push(m.address.toString());
        } catch (e) {}
    }
    return hits;
};
rpc.exports.ctx = function (addr, n) {
    const u = new Uint8Array(ptr(addr).readByteArray(n));
    let s = '';
    for (let i = 0; i < u.length; i++) s += (u[i] >= 32 && u[i] < 127) ? String.fromCharCode(u[i]) : '.';
    return s;
};
