
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.find = function (nm) {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const out = [];
        const walk = (k, path, depth) => {
            if (k.name === nm) {
                out.push({ full: path + '/' + k.name, fields: k.fields.map(f => f.name + ':' + f.offset + ':' + f.type.name), methods: k.methods.map(m => (m.isStatic ? 'S ' : 'I ') + m.name + '(' + m.parameterCount + ')->' + m.returnType.name) });
            }
            if (depth > 0) { try { for (const n of k.nestedClasses) walk(n, path + '/' + k.name, depth - 1); } catch (e) {} }
        };
        for (const k of img.classes) walk(k, '', 2);
        return out;
    });
};
