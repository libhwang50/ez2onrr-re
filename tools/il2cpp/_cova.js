
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.v = function () {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const da = img.class('da');
        const co = da.nestedClasses.find(n => n.name === 'co');
        const out = {};
        for (const m of co.methods) {
            out[m.name + '(' + m.parameterCount + ')'] = m.virtualAddress.toString();
        }
        // also the static field offsets inside da.co
        out.__fields = co.fields.map(f => f.name + ':' + f.offset + ':' + f.type.name);
        return out;
    });
};
