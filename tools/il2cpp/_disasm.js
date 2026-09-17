
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.d = function (addr, n) {
    return onMain(() => {
        const u = new Uint8Array(ptr(addr).readByteArray(n));
        let h = ''; for (let i = 0; i < u.length; i++) h += u[i].toString(16).padStart(2, '0');
        return h;
    });
};
rpc.exports.ea = function () {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const k = img.class('ea');
        const m = k.methods.find(x => x.name === 'jux');
        return { va: m.virtualAddress.toString(), rva: m.relativeVirtualAddress.toString(16) };
    });
};
rpc.exports.daclass = function () {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const da = img.class('da');
        return { classPtr: da.handle.toString(), sfd: da.staticFieldsData.toString() };
    });
};
