
rpc.exports.cls = function (name) {
    return Il2Cpp.perform(() => {
        try {
            const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
            const k = img.class(name);
            return { name: k.name, fields: k.fields.map(f => f.name + ":" + f.type.name + (f.isStatic ? " [S]" : "")), methods: k.methods.map(m => m.name + "(" + m.parameterCount + ")->" + m.returnType.name + (m.isStatic ? " [S]" : "")) };
        } catch (e) { return { error: '' + e }; }
    });
};
rpc.exports.invokeStr = function (cls, method, hexArg) {
    return Il2Cpp.perform(() => {
        try {
            const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
            const k = img.class(cls);
            const m = k.method(method, hexArg ? 1 : 0);
            let out;
            if (hexArg) { const byteClass = Il2Cpp.corlib.class("System.Byte"); const a = []; for (let i = 0; i < hexArg.length; i += 2) a.push(parseInt(hexArg.substr(i, 2), 16)); out = k.method(method, 1).invoke(Il2Cpp.array(byteClass, a)); }
            else out = m.invoke();
            return { val: '' + out };
        } catch (e) { return { error: '' + (e && e.message ? e.message : e) }; }
    });
};
