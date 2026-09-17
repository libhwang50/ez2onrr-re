
rpc.exports.disp = function (disp) {
    const base = 0x6ffff23c0000, size = 0x48f4000, CH = 0x100000;
    const d = disp >>> 0;
    const b0 = d & 0xff, b1 = (d >> 8) & 0xff, b2 = (d >> 16) & 0xff, b3 = (d >> 24) & 0xff;
    const hits = [];
    for (let off = 0; off < size; off += CH) {
        let buf;
        try { buf = new Uint8Array(ptr(base + off).readByteArray(Math.min(CH, size - off))); } catch (e) { continue; }
        for (let i = 0; i + 8 <= buf.length; i++) {
            // mov r64, [r64+disp32] : 48 8B <modrm&0xC0==0x80> <disp32>
            if (buf[i] === 0x48 && buf[i + 1] === 0x8b && (buf[i + 2] & 0xc0) === 0x80
                && buf[i + 3] === b0 && buf[i + 4] === b1 && buf[i + 5] === b2 && buf[i + 6] === b3) {
                hits.push(base + off + i);
            }
            // mov r32, [r64+disp32] : 8B <modrm&0xC0==0x80> <disp32>
            if (buf[i] === 0x8b && (buf[i + 1] & 0xc0) === 0x80
                && buf[i + 2] === b0 && buf[i + 3] === b1 && buf[i + 4] === b2 && buf[i + 5] === b3) {
                hits.push(base + off + i);
            }
        }
    }
    return hits;
};
