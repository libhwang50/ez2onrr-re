
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.r32 = function (a) { try { return ptr(a).readU32(); } catch (e) { return null; } };
rpc.exports.rptr = function (a) { try { return ptr(a).readPointer().toString(); } catch (e) { return null; } };
rpc.exports.rbytes = function (a, n) { try { const u = new Uint8Array(ptr(a).readByteArray(n)); let s=''; for (let i=0;i<u.length;i++) s+=String.fromCharCode(u[i]); return s; } catch (e) { return null; } };
rpc.exports.read = function (addr, n) { try { const u = new Uint8Array(ptr(addr).readByteArray(n)); return Array.from(u); } catch (e) { return null; } };
rpc.exports.vaddr = function (cls, name, n) {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const k = img.class(cls);
        for (const m of k.methods) if (m.name === name && m.parameterCount === n) return m.virtualAddress.toString();
        return null;
    });
};
