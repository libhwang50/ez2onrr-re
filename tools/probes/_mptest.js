
rpc.exports.t = function () {
    const out = {};
    const p = Memory.alloc(0x1000);
    p.writeByteArray([1, 2, 3, 4]);
    out.wrote = p.readU8();
    try { Memory.protect(p, 0x1000, '---'); out.protect = 'ok'; } catch (e) { out.protect = 'ERR:' + e; }
    try { out.afterProtect = p.readU8(); } catch (e) { out.afterProtect = 'THREW:' + e; }
    try { Memory.protect(p, 0x1000, 'rw-'); out.restore = 'ok'; } catch (e) { out.restore = 'ERR:' + e; }
    try { out.afterRestore = p.readU8(); } catch (e) { out.afterRestore = 'THREW:' + e; }
    return out;
};
