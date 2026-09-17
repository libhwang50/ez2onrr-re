
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.wx = function () {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const zf = img.class('zf');
        const out = {};
        const walk = (k, path, d) => {
            if (k.name === 'wx' || k.name === 'wy' || k.name === 'wz') {
                out[path + '/' + k.name] = {
                    fields: k.fields.map(f => f.name + ':' + f.offset + ':' + f.type.name),
                    methods: k.methods.map(m => (m.isStatic?'S ':'I ') + m.name + '(' + m.parameterCount + ')->' + m.returnType.name)
                };
            }
            if (d > 0) { try { for (const n of k.nestedClasses) walk(n, path + '/' + k.name, d - 1); } catch (e) {} }
        };
        walk(zf, 'zf', 1);
        return out;
    });
};
