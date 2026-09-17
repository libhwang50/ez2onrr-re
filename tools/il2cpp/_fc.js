// Dynamic call-site scanner (E8 rel32) using the live module base/size.
// rpc.exports.fc(targets: string[]) -> {base,size,hits:[{site,dest}],bad}
rpc.exports.fc = function (targets) {
    const mod = Process.getModuleByName("GameAssembly.dll");
    const base = mod.base.toInt32 ? Number(mod.base.toString()) : Number(mod.base);
    const baseNum = parseInt(mod.base.toString(), 16);
    const size = mod.size;
    const CH = 0x100000;
    const tset = {};
    for (const t of targets) tset[parseInt(t, 16)] = true;
    const hits = [];
    let bad = 0;
    for (let off = 0; off < size; off += CH) {
        let buf;
        try { buf = new Uint8Array(ptr(baseNum + off).readByteArray(Math.min(CH, size - off))); }
        catch (e) { bad++; continue; }
        for (let i = 0; i + 5 <= buf.length; i++) {
            if (buf[i] !== 0xe8) continue;
            let rel = (buf[i + 1] | (buf[i + 2] << 8) | (buf[i + 3] << 16) | (buf[i + 4] << 24));
            const site = baseNum + off + i;
            const dest = site + 5 + rel;
            if (tset[dest] === true) hits.push({ dest: dest, site: site });
        }
    }
    return { base: mod.base.toString(), size: size, bad: bad, hits: hits };
};
