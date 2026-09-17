
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
function arr(hex) {
    const bc = Il2Cpp.corlib.class("System.Byte");
    const a = []; for (let i = 0; i < hex.length; i += 2) a.push(parseInt(hex.substr(i, 2), 16));
    return Il2Cpp.array(bc, a);
}
rpc.exports.f = function (cls, method, hex, field, isInst) {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const k = img.class(cls);
        const inst = field ? k.field(field).value : k.field('instance').value;
        const m = isInst ? inst.method(method, 1) : k.method(method, 1);
        const out = m.invoke(arr(hex));
        let s = null; try { s = out.content !== undefined ? out.content : ('' + out); } catch (e) { s = '' + out; }
        return { type: out && out.class ? out.class.name : typeof out, value: s };
    });
};
