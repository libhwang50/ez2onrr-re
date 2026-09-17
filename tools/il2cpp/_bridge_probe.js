
rpc.exports.probe = function (cls, methodName, hexArg, withThis) {
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
            const n = out.length;
            let p; try { p = out.elements.handle; } catch (e) { p = out.handle.add(0x20); }
            const u8 = new Uint8Array(p.readByteArray(Math.min(n, 64)));
            let hex = ''; for (let i = 0; i < u8.length; i++) hex += u8[i].toString(16).padStart(2, '0');
            res.len = n; res.head = hex;
            return res;
        } catch (e) { res.error = '' + (e && e.message ? e.message : e); return res; }
    });
};
rpc.exports.probeStatic = function (cls, methodName, hexArg) { return this.probe(cls, methodName, hexArg, false); };
