
// Find `mov r64,[r64+0xb8]` (48 8B <modrm mode=10> B8 00 00 00) followed within N bytes
// by `add r64, imm32` (48 81 <modrm mod=11> imm32) with imm32 == target offset.
rpc.exports.scan = function (offset, window) {
    const base = 0x6ffff23c0000, size = 0x48f4000, CH = 0x100000;
    const W = window || 32;
    const o0 = offset & 0xff, o1 = (offset >> 8) & 0xff, o2 = (offset >> 16) & 0xff, o3 = (offset >> 24) & 0xff;
    const hits = [];
    for (let off = 0; off < size; off += CH) {
        let buf;
        try { buf = new Uint8Array(ptr(base + off).readByteArray(Math.min(CH, size - off))); } catch (e) { continue; }
        for (let i = 0; i + 7 <= buf.length; i++) {
            // mov r64, [r64+0xb8]  -> 48 8B <modrm & 0xC7 == 0x80?> ; require mod=10, disp32=0xb8
            if (buf[i] !== 0x48 || buf[i + 1] !== 0x8b) continue;
            const m = buf[i + 2];
            if ((m & 0xc0) !== 0x80) continue;              // mod=10 (disp32)
            if (buf[i + 3] !== 0xb8 || buf[i + 4] !== 0x00 || buf[i + 5] !== 0x00 || buf[i + 6] !== 0x00) continue;
            // search forward within W bytes for add r64, imm32==offset (48 81 <mod=11> xx xx xx xx)
            for (let j = i + 7; j < Math.min(i + 7 + W, buf.length - 7); j++) {
                if (buf[j] === 0x48 && buf[j + 1] === 0x81 && (buf[j + 2] & 0xc0) === 0xc0
                    && buf[j + 3] === o0 && buf[j + 4] === o1 && buf[j + 5] === o2 && buf[j + 6] === o3) {
                    hits.push({ load: base + off + i, add: base + off + j, delta: j - i });
                    break;
                }
            }
        }
    }
    return hits;
};
