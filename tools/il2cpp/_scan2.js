
rpc.exports.range = function (base, size, targets) {
    const tset = {};
    for (const t of targets) tset[parseInt(t, 16)] = true;
    let buf;
    try { buf = new Uint8Array(ptr(base).readByteArray(size)); } catch (e) { return { err: '' + e }; }
    const hits = [];
    for (let i = 0; i + 5 <= buf.length; i++) {
        if (buf[i] !== 0xe8) continue;
        const rel = (buf[i + 1] | (buf[i + 2] << 8) | (buf[i + 3] << 16) | (buf[i + 4] << 24));
        const site = base + i;
        const dest = site + 5 + rel;
        if (tset[dest] === true) hits.push({ site: site, dest: dest });
    }
    return { len: buf.length, hits: hits };
};
