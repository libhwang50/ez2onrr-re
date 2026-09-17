
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.mptr = function (cls, method, n) {
    return onMain(() => {
        try {
            const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
            const k = img.class(cls);
            const m = k.methods.find(x => x.name === method);
            if (!m) return { err: 'no method' };
            const va = m.virtualAddress;
            const rva = m.relativeVirtualAddress;
            const code = new Uint8Array(va.readByteArray(n));
            let h = ''; for (let i = 0; i < code.length; i++) h += code[i].toString(16).padStart(2, '0');
            return { cls: cls, method: method, va: va.toString(), rva: rva.toString(16), head: h };
        } catch (e) { return { err: '' + (e && e.message ? e.message : e) }; }
    });
};
rpc.exports.modinfo = function () {
    return onMain(() => {
        const out = [];
        const mod = Process.getModuleByName("GameAssembly.dll");
        out.push({ base: mod.base.toString(), size: mod.size });
        for (const s of mod.enumerateSections()) out.push({ name: s.name, addr: s.address.toString(), size: s.size });
        return out;
    });
};
