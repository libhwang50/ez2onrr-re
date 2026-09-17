
rpc.exports.test = function () {
    return Il2Cpp.perform(() => {
        const out = {};
        out.assemblies = Il2Cpp.domain.assemblies.map(a => a.name);
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const klass = img.class("qe");
        out.qeName = klass.name;
        out.qeMethods = klass.methods.map(m => m.name + "(" + m.parameterCount + ")->" + m.returnType.name);
        return out;
    });
};
