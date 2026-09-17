
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.sig = function (cls) {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const k = img.class(cls);
        const out = [];
        for (const m of k.methods) {
            let ps = []; try { for (let i = 0; i < m.parameterCount; i++) ps.push(m.parameters[i].type.name.replace('System.','')); } catch (e) { ps = ['?']; }
            const rt = m.returnType.name.replace('System.','');
            // only interesting: byte[]/String in or out
            const sig = ps.join(',') + '->' + rt;
            if (/Byte\[\]|String/.test(sig)) out.push((m.isStatic?'S ':'I ') + m.name + '(' + sig + ')');
        }
        return out;
    });
};
