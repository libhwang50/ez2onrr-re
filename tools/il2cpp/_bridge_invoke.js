
function hexToJs(hex) { const a = []; for (let i = 0; i < hex.length; i += 2) a.push(parseInt(hex.substr(i, 2), 16)); return a; }
function arrToHex(a) { try { const n = a.length; const out = []; const lim = Math.min(n, 64); for (let i = 0; i < lim; i++) out.push(a.get(i)); return { len: n, hex: out.map(x => (x & 0xff).toString(16).padStart(2, '0')).join('') }; } catch (e) { return { err: '' + e }; } }

rpc.exports.tryInvoke = function (cls, methodName, hexArg) {
    return Il2Cpp.perform(() => {
        const res = { cls: cls, method: methodName };
        try {
            const byteClass = Il2Cpp.corlib.class("System.Byte");
            const arg = Il2Cpp.array(byteClass, hexToJs(hexArg));
            res.argLen = arg.length;
            const klass = Il2Cpp.domain.assembly("Assembly-CSharp").image.class(cls);
            const method = klass.method(methodName, 1);
            res.retType = method.returnType.name;
            const out = method.invoke(arg);
            res.outHandle = out && out.handle ? out.handle.toString() : ('' + out);
            try { if (out && typeof out.length === 'number') { res.result = arrToHex(out); } }
            catch (e) { res.readErr = '' + e; }
            return res;
        } catch (e) { res.error = '' + (e && e.stack ? e.stack : e); return res; }
    });
};
