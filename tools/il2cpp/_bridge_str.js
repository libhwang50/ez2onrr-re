
rpc.exports.probeStr = function (cls, methodName, hexArg, withThis) {
    return Il2Cpp.perform(() => {
        const res = { cls: cls, method: methodName, withThis: withThis };
        try {
            const a = []; for (let i = 0; i < hexArg.length; i += 2) a.push(parseInt(hexArg.substr(i, 2), 16));
            const byteClass = Il2Cpp.corlib.class("System.Byte");
            const arg = Il2Cpp.array(byteClass, a);
            const klass = Il2Cpp.domain.assembly("Assembly-CSharp").image.class(cls);
            let out;
            if (withThis) { const inst = klass.field("instance").value; out = inst.method(methodName, 1).invoke(arg); }
            else { out = klass.method(methodName, 1).invoke(arg); }
            res.val = '' + out;
            return res;
        } catch (e) { res.error = '' + (e && e.message ? e.message : e); return res; }
    });
};
