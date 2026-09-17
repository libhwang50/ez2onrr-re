
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.tables = function () {
    return onMain(() => {
        const out = [];
        const walk = (k, p, d) => {
            let hit = null;
            try {
                for (const f of k.fields) {
                    if (!f.isStatic) continue;
                    const t = '' + f.type.name;
                    if (t === 'System.Byte[]' || t === 'System.UInt32[]' || t === 'System.Int32[]' || t === 'System.Byte[][]' || t === 'System.UInt32[][]') {
                        hit = { cls: p + '/' + k.name, field: f.name, type: t };
                        break;
                    }
                }
            } catch (e) {}
            if (hit) {
                try {
                    hit.methods = k.methods.map(m => (m.isStatic?'S ':'I ') + m.name + '(' + m.parameterCount + ')->' + m.returnType.name).slice(0, 30);
                    hit.nMethods = k.methods.length;
                } catch (e) { hit.methods = []; }
                out.push(hit);
            }
            if (d > 0) { try { for (const n of k.nestedClasses) walk(n, p + '/' + k.name, d - 1); } catch (e) {} }
        };
        for (const a of Il2Cpp.domain.assemblies) { let i; try { i = a.image; } catch (e) { continue; } for (const k of i.classes) walk(k, a.name, 1); }
        return out;
    });
};
rpc.exports.byteklass = function () {
    return onMain(() => {
        const bc = Il2Cpp.corlib.class("System.Byte");
        const a = Il2Cpp.array(bc, [1,2,3]);
        return { arrObj: a.handle.toString(), klass: a.handle.readPointer().toString() };
    });
};
