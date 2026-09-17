
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.nm = function () {
    return onMain(() => {
        const m = {};
        const walk = (k, p, d) => {
            let kn = p + '.' + k.name;
            try { for (const meth of k.methods) { const a = meth.virtualAddress; if (!a.isNull()) m[a.toString().toLowerCase()] = kn + '.' + meth.name + '/' + meth.parameterCount; } } catch (e) {}
            if (d > 0) { try { for (const n of k.nestedClasses) walk(n, kn, d - 1); } catch (e) {} }
        };
        for (const asm of Il2Cpp.domain.assemblies) { let i; try { i = asm.image; } catch (e) { continue; } for (const k of i.classes) walk(k, asm.name, 1); }
        return m;
    });
};
rpc.exports.base = function () { return Process.getModuleByName("GameAssembly.dll").base.toString(); };
