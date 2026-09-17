globalThis.hexToJs = function(hex) { const a = []; for (let i = 0; i < hex.length; i += 2) a.push(parseInt(hex.substr(i, 2), 16)); return a; }
globalThis.arrToHex = function(a) { try { const n = a.length; const out = []; for (let i = 0; i < Math.min(n, 32); i++) out.push(a.get(i)); return { len: n, hex: out.map(x => (x & 0xff).toString(16).padStart(2, '0')).join('') }; } catch (e) { return { err: '' + e }; } }
globalThis.isEzff = function(h) { return h && h.slice(0, 8).toLowerCase() === '455a4646'; }

rpc.exports.tryInstance = function (cls, methodName, hexArg) {
    return Il2Cpp.perform(() => {
        const res = { cls: cls, method: methodName, kind: 'instance' };
        try {
            const byteClass = Il2Cpp.corlib.class("System.Byte");
            const arg = Il2Cpp.array(byteClass, hexToJs(hexArg));
            const klass = Il2Cpp.domain.assembly("Assembly-CSharp").image.class(cls);
            const inst = klass.field("instance").value;
            res.inst = inst.handle.toString();
            const out = inst.method(methodName, 1).invoke(arg);
            res.result = arrToHex(out);
            res.isEzff = isEzff(res.result && res.result.hex);
            return res;
        } catch (e) { res.error = '' + (e && e.message ? e.message : e); return res; }
    });
};
rpc.exports.tryStatic = function (cls, methodName, hexArgs) {
    return Il2Cpp.perform(() => {
        const res = { cls: cls, method: methodName, kind: 'static' };
        try {
            const byteClass = Il2Cpp.corlib.class("System.Byte");
            const args = hexArgs.map(h => Il2Cpp.array(byteClass, hexToJs(h)));
            const klass = Il2Cpp.domain.assembly("Assembly-CSharp").image.class(cls);
            const out = klass.method(methodName, hexArgs.length).invoke(...args);
            res.result = arrToHex(out);
            res.isEzff = isEzff(res.result && res.result.hex);
            return res;
        } catch (e) { res.error = '' + (e && e.message ? e.message : e); return res; }
    });
};
