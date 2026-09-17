
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.read = function (addr, n) {
    try {
        const u = new Uint8Array(ptr(addr).readByteArray(n));
        return Array.from(u);
    } catch (e) { return null; }
};
rpc.exports.lit = function (addr) {
    try {
        // IL2CPP string literal: pointer to a char* (utf8) or a managed string
        const p = ptr(addr);
        // try: addr itself points to utf8
        try { const s = p.readUtf8String(); if (s && s.length > 0 && s.length < 200) return { kind: 'utf8', s: s }; } catch (e) {}
        return null;
    } catch (e) { return null; }
};
rpc.exports.vaddr = function (cls, name, n) {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const k = img.class(cls);
        for (const m of k.methods) if (m.name === name && m.parameterCount === n) return m.virtualAddress.toString();
        return null;
    });
};
