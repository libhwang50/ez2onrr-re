
globalThis.__bt = [];
globalThis.__on = false;
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
function vaddr(cls, name, n, asm) {
    for (const a of Il2Cpp.domain.assemblies) {
        if (asm && a.name !== asm) continue;
        let img; try { img = a.image; } catch (e) { continue; }
        const k = img.classes.find(c => c.name === cls);
        if (!k) continue;
        for (const m of k.methods) if (m.name === name && (n === undefined || m.parameterCount === n)) return m.virtualAddress;
    }
    return null;
}
rpc.exports.arm = function () {
    return onMain(() => {
        const targets = [
            ['mscorlib','RijndaelManaged','.ctor',0],
            ['mscorlib','Rijndael','.ctor',0],
            ['mscorlib','RijndaelManagedTransform','.ctor',7],
            ['mscorlib','RijndaelManaged','CreateDecryptor',2],
            ['System.Core','AesManaged','.ctor',0],
            ['System.Core','AesCryptoServiceProvider','.ctor',0],
            ['mscorlib','Aes','Create',0],
        ];
        const armed = [];
        for (const [asm, cls, meth, n] of targets) {
            let va = null;
            try { va = vaddr(cls, meth, n, asm); } catch (e) {}
            if (!va) { armed.push(asm + ':' + cls + '.' + meth + ' = NOT FOUND'); continue; }
            try {
                Interceptor.attach(va, {
                    onEnter(args) {
                        try {
                            if (globalThis.__bt.length >= 200) return;
                            const bt = Thread.backtrace(this.context, Backtracer.ACCURATE).map(p => p.toString());
                            globalThis.__bt.push({ fn: cls + '.' + meth, v: va.toString(), bt: bt.slice(0, 8), t: Date.now() });
                        } catch (e) {}
                    }
                });
                armed.push(asm + ':' + cls + '.' + meth + ' @' + va);
            } catch (e) { armed.push(cls + '.' + meth + ' HOOK-ERR ' + e); }
        }
        globalThis.__on = true;
        return armed;
    });
};
rpc.exports.bt = function () { const r = globalThis.__bt.slice(); return r; };
rpc.exports.clear = function () { globalThis.__bt = []; return 'cleared'; };
