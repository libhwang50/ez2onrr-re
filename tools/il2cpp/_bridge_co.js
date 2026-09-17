
rpc.exports.coInfo = function () {
    return Il2Cpp.perform(() => {
        const out = {};
        try {
            const klass = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("co");
            out.name = klass.name;
            out.fields = klass.fields.map(f => f.name + ":" + f.type.name);
            out.methods = klass.methods.map(m => m.name + "(" + m.parameterCount + ")->" + m.returnType.name);
            const inst = klass.tryField ? null : null;
            return out;
        } catch (e) { out.error = '' + (e && e.message ? e.message : e); return out; }
    });
};
rpc.exports.callGetter = function (methodName) {
    return Il2Cpp.perform(() => {
        const res = { method: methodName };
        try {
            const klass = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("co");
            if (!globalThis.__coInst) {
                const f = klass.tryField("instance");
                if (!f) { res.error = 'no instance field'; return res; }
                globalThis.__coInst = f.value;
            }
            const out = globalThis.__coInst.method(methodName, 0).invoke();
            res.type = out && out.class ? out.class.name : typeof out;
            if (out && typeof out.length === 'number') {
                const n = out.length; let p; try { p = out.elements.handle; } catch (e) { p = out.handle.add(0x20); }
                const u8 = new Uint8Array(p.readByteArray(Math.min(n, 64))); let h = ''; for (let i = 0; i < u8.length; i++) h += u8[i].toString(16).padStart(2, '0');
                res.len = n; res.hex = h;
            } else { res.val = '' + out; }
            return res;
        } catch (e) { res.error = '' + (e && e.message ? e.message : e); return res; }
    });
};
