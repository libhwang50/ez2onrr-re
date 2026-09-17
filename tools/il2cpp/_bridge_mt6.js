
function onMain(fn) {
    return Il2Cpp.perform(() => {
        const tid = Il2Cpp.mainThread.id;
        return Process.runOnThread(tid, () => fn());
    });
}
function arr(hex) {
    const bc = Il2Cpp.corlib.class("System.Byte");
    const a = []; for (let i = 0; i < hex.length; i += 2) a.push(parseInt(hex.substr(i, 2), 16));
    return Il2Cpp.array(bc, a);
}
rpc.exports.sig = function (cls, method) {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const k = img.class(cls);
        const out = {};
        for (const m of k.methods) if (m.name === method) {
            let ps = []; try { for (let i = 0; i < m.parameterCount; i++) ps.push(m.parameters[i].type.name + ' ' + m.parameters[i].name); } catch (e) { ps.push('?'); }
            out[(m.isStatic ? 'S:' : 'I:') + m.parameterCount] = ps.join(', ');
        }
        return out;
    });
};
rpc.exports.s1 = function (cls, method, str) {
    return onMain(() => {
        try {
            const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
            const out = img.class(cls).method(method, 1).invoke(Il2Cpp.string(str));
            return out === null ? 'NULL' : ('' + out).slice(0, 400);
        } catch (e) { return { err: '' + (e && e.message ? e.message : e) }; }
    });
};
rpc.exports.sbb = function () {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const out = [];
        for (const k of img.classes) {
            let ms; try { ms = k.methods; } catch (e) { continue; }
            for (const m of ms) {
                if (m.isStatic && m.returnType.name === 'System.Byte[]' && m.parameterCount >= 1 && m.parameterCount <= 3) {
                    let ps = []; try { for (let i = 0; i < m.parameterCount; i++) ps.push(m.parameters[i].type.name.replace('System.','')); } catch (e) { ps = ['?']; }
                    out.push(k.name + '.' + m.name + '(' + ps.join(',') + ')');
                }
            }
        }
        return out;
    });
};
