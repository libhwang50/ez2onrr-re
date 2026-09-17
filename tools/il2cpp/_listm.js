
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.lm = function (cls, filter) {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const k = img.class(cls);
        const out = [];
        for (const m of k.methods) {
            let ps = []; try { for (let i = 0; i < m.parameterCount; i++) ps.push(m.parameters[i].type.name.replace('System.', '').replace('System.Collections.Generic.', '')); } catch (e) { ps = ['?']; }
            const sig = (m.isStatic ? 'S ' : 'I ') + m.name + '(' + ps.join(',') + ')->' + m.returnType.name.replace('System.', '');
            if (!filter || sig.indexOf(filter) >= 0) out.push(sig);
        }
        return out;
    });
};
