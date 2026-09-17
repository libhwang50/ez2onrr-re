
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.info = function () {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const da = img.class('da');
        const mod = Process.getModuleByName("GameAssembly.dll");
        return { base: mod.base.toString(), size: mod.size, daClass: da.handle.toString(), sfd: da.staticFieldsData.toString() };
    });
};
rpc.exports.d = function (addr, n) {
    return onMain(() => {
        const u = new Uint8Array(ptr(addr).readByteArray(n));
        let h = ''; for (let i = 0; i < u.length; i++) h += u[i].toString(16).padStart(2, '0');
        return h;
    });
};
