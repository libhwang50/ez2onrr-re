
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
function tohex(buf) { const u = new Uint8Array(buf); let h = ''; for (let i = 0; i < u.length; i++) h += u[i].toString(16).padStart(2, '0'); return h; }
rpc.exports.dump = function (cls, method, n) {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const m = img.class(cls).methods.find(x => x.name === method);
        return { va: m.virtualAddress.toString(), rva: m.relativeVirtualAddress.toString(16), hex: tohex(m.virtualAddress.readByteArray(n)) };
    });
};
