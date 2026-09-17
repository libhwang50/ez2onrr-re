
function onMain(fn) {
    return Il2Cpp.perform(() => { const tid = Il2Cpp.mainThread.id; return Process.runOnThread(tid, () => fn()); });
}
rpc.exports.who = function (typ) {
    return onMain(() => {
        const out = [];
        for (const asmName of ['Assembly-CSharp']) {
            const img = Il2Cpp.domain.assembly(asmName).image;
            for (const k of img.classes) {
                let ms; try { ms = k.methods; } catch (e) { continue; }
                for (const m of ms) {
                    let ps = []; try { for (let i = 0; i < m.parameterCount; i++) ps.push(m.parameters[i].type.name); } catch (e) { continue; }
                    if (ps.some(p => p === typ || p.endsWith('.' + typ))) {
                        out.push(k.name + '.' + m.name + '(' + ps.join(',') + ')->' + m.returnType.name + (m.isStatic ? ' [S]' : ''));
                    }
                }
            }
        }
        return out;
    });
};
rpc.exports.findClass = function (nm) {
    return onMain(() => {
        const out = [];
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        for (const k of img.classes) {
            if (k.name === nm) out.push({ where: 'top', fields: k.fields.map(f => f.name + ':' + f.type.name), methods: k.methods.map(m => m.name + '(' + m.parameterCount + ')->' + m.returnType.name) });
            try { for (const n of k.nestedClasses) if (n.name === nm) out.push({ where: k.name + '/', fields: n.fields.map(f => f.name + ':' + f.type.name), methods: n.methods.map(m => m.name + '(' + m.parameterCount + ')->' + m.returnType.name) }); } catch (e) {}
        }
        return out;
    });
};
