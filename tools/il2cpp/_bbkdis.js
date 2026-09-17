
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.vas = function () {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const k = img.class('bbk');
        const o = {};
        for (const m of k.methods) o[m.name + '/' + m.parameterCount] = m.virtualAddress.toString();
        return o;
    });
};
