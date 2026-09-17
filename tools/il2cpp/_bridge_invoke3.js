
rpc.exports.tryInstance = function (cls, methodName, hexArg) {
    return Il2Cpp.perform(() => {
        const res = { cls: cls, method: methodName, kind: 'instance' };
        try {
            const a = []; for (let i = 0; i < hexArg.length; i += 2) a.push(parseInt(hexArg.substr(i, 2), 16));
            const byteClass = Il2Cpp.corlib.class("System.Byte");
            const arg = Il2Cpp.array(byteClass, a);
            const klass = Il2Cpp.domain.assembly("Assembly-CSharp").image.class(cls);
            const inst = klass.field("instance").value;
            const out = inst.method(methodName, 1).invoke(arg);
            const n = out.length; const o = []; for (let i = 0; i < Math.min(n, 32); i++) o.push(out.get(i));
            res.len = n; res.hex = o.map(x => (x & 0xff).toString(16).padStart(2, '0')).join('');
            res.isEzff = res.hex.slice(0, 8).toLowerCase() === '455a4646';
            return res;
        } catch (e) { res.error = '' + (e && e.message ? e.message : e); return res; }
    });
};
rpc.exports.tryStatic = function (cls, methodName, hexArgs) {
    return Il2Cpp.perform(() => {
        const res = { cls: cls, method: methodName, kind: 'static' };
        try {
            const byteClass = Il2Cpp.corlib.class("System.Byte");
            const args = hexArgs.map(h => { const a = []; for (let i = 0; i < h.length; i += 2) a.push(parseInt(h.substr(i, 2), 16)); return Il2Cpp.array(byteClass, a); });
            const klass = Il2Cpp.domain.assembly("Assembly-CSharp").image.class(cls);
            const out = klass.method(methodName, hexArgs.length).invoke(...args);
            const n = out.length; const o = []; for (let i = 0; i < Math.min(n, 32); i++) o.push(out.get(i));
            res.len = n; res.hex = o.map(x => (x & 0xff).toString(16).padStart(2, '0')).join('');
            res.isEzff = res.hex.slice(0, 8).toLowerCase() === '455a4646';
            return res;
        } catch (e) { res.error = '' + (e && e.message ? e.message : e); return res; }
    });
};
