
globalThis.__hits = [];
rpc.exports.t = function () {
    const out = {};
    const p = Memory.alloc(0x1000);
    p.writeByteArray([0xaa, 0xbb, 0xcc, 0xdd]);
    try {
        MemoryAccessMonitor.enable({ base: p, size: 0x1000 }, {
            onAccess(d) { globalThis.__hits.push({ op: d.operation, from: d.from.toString(), addr: d.address.toString() }); }
        });
        out.armed = true;
    } catch (e) { out.armed = 'ERR:' + e; }
    // read from THIS thread first
    try { out.sameThread = p.readU8(); } catch (e) { out.sameThread = 'THREW'; }
    // then from the game's main thread
    try {
        Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => { try { return 'x' + p.readU8(); } catch (e) { return 'threw'; } }));
        out.otherThread = 'done';
    } catch (e) { out.otherThread = 'ERR:' + e; }
    return out;
};
rpc.exports.hits = function () { return globalThis.__hits; };
