
rpc.exports.fc = function (targets) {
    const base = 0x6ffff23c0000, size = 0x48f4000;
    const CH = 0x100000;
    const tset = {};
    for (const t of targets) tset[parseInt(t, 16)] = true;
    const hits = [];
    let scanned = 0, bad = 0;
    for (let off = 0; off < size; off += CH) {
        let buf;
        try { buf = new Uint8Array(ptr(base + off).readByteArray(Math.min(CH, size - off))); }
        catch (e) { bad++; continue; }
        scanned += buf.length;
        for (let i = 0; i + 5 <= buf.length; i++) {
            if (buf[i] !== 0xe8) continue;
            let rel = (buf[i + 1] | (buf[i + 2] << 8) | (buf[i + 3] << 16) | (buf[i + 4] << 24));
            const site = base + off + i;
            const dest = site + 5 + rel;
            if (tset[dest] === true) hits.push({ dest: dest, site: site });
        }
    }
    return { scanned: scanned, bad: bad, hits: hits };
};
